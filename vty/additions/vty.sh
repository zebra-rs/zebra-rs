# Copyright (C) 2026 zebra-rs project.
#
# This software is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with This software.  If not, see
# <http://www.gnu.org/licenses/>.

_cli_interactive_setup ()
{
  case "$-" in
    *i*)
      interactive="interactive"
      ;;
    *)
      interactive=""
      ;;
  esac
}
_cli_interactive_setup

# if [[ $interactive ]]; then
#   if [ ! `basename "/$0"` = "cli" ];then
#    return 0
#   fi
# fi

# CLI command tool name.
cli_command=vtyhelper

declare -x CLI_MODE="exec"
declare -x CLI_MODE_STR="Exec"
declare -x CLI_MODE_PROMPT=""
_cli_in_config_group ()
{
  id -nG 2>/dev/null | tr ' \t' '\n' | grep -qx zebra-rs
}

declare -x CLI_PRIVILEGE=1

# Daemon-configured `system hostname` for the prompt; empty means
# unconfigured and the prompt falls back to the OS hostname. Seeded
# at startup via `vtyhelper -H` and re-synced by
# _cli_hostname_refresh after every executed command, so a committed
# `set system hostname` shows up on the very next prompt.
declare -x CLI_HOSTNAME=""
declare -a _cli_array_completions
declare -A _cli_array_helps
declare -A _cli_array_pre

# 1 once the daemon answered with at least one first-level command,
# 0 otherwise. Used to retry registration on the next TAB / command
# when vty started while the zebra-rs daemon was still down.
declare -i _cli_first_level_registered=0

# 1 once this shell has entered configure mode. Gates the exit-time
# uncommitted-changes prompt in _cli_exit_hook: the candidate config is
# global to the daemon, so without this gate an operator who only ran
# `show` would be asked about — and could discard — someone else's
# pending edits. Sticky for the shell's life, including across `disable`: a
# session that dropped back to View should still be told, and get the
# "admin role required" answer, rather than silently walking away.
declare -i _cli_entered_configure=0

# The admin-role timer's pid, empty when none runs (see
# _cli_admin_check).
_cli_admin_timer_pid=""

# A one-line notice a trap left for the operator. The vty's
# cli_signal_event_hook (vtysh.c) prints it at once when readline is
# waiting for input; _cli_notice_flush prints it before the next prompt
# otherwise.
_cli_notice=""

# vtyhelper's warning from the last first-level registration that could
# not reach the daemon; empty when it could.
_cli_unreachable_msg=""

# Seconds the admin role had left at the last question (_cli_admin_left,
# or the refresh after a command): 0 none, -1 never lapses, empty when
# the daemon could not say.
_cli_admin_secs=""

# $SECONDS when the role's time, as last asked, runs out; 0 when no timer
# waits for it.
declare -i _cli_admin_deadline=0

# Seconds before asking again when the daemon could not be asked
# (CLI_ADMIN_RETRY lets the tests wait less).
_cli_admin_retry=${CLI_ADMIN_RETRY:-60}

# Set (local) while _cli_exec retries a refused line with the role just
# taken, which is not retried again.
_cli_retrying=""

COMP_WORDBREAKS=${COMP_WORDBREAKS//:/}

_cli_prompt_setup ()
{
  CLI_MODE_CHAR=">"

  if (( ${CLI_PRIVILEGE} >= 15 ));then
    CLI_MODE_CHAR="#"
  fi

  if [[ ${CLI_MODE} == "configure" ]];then
    CLI_MODE_CHAR="#"
  fi

  # Mode tag (e.g. "(config)") follows the mode character so the user
  # sees `host#(config)` in configure mode and a plain `host>` /
  # `host#` in exec mode (where CLI_MODE_PROMPT is empty). The name is
  # the daemon-configured `system hostname` when set, else the OS
  # hostname.
  export PS1="${CLI_HOSTNAME:-$(hostname)}${CLI_MODE_CHAR}${CLI_MODE_PROMPT}"
}

_cli_pager_setup ()
{
  # NOTE: deliberately no --raw-control-chars (-R). `show` output is plain
  # ASCII (no ANSI colour is emitted anywhere), and -R makes less mis-count
  # how many screen rows a wrapped line occupies: a `show ip route` entry that
  # is one column too wide (e.g. an ECMP leg with an MPLS label + "weight 1")
  # folds onto two physical rows, and under -R less overshoots the first page
  # so the top lines scroll off before the ":" prompt appears. Without -R less
  # counts the folded rows correctly and the first screen starts at the top.
  # Re-add -R only alongside genuine colour output, and re-test wrapping.
  [[ -z ${CLI_PAGER} ]] && \
    CLI_PAGER="less \
      --no-lessopen\
      --quit-at-eof\
      --quit-if-one-screen\
      --squeeze-blank-lines\
      --no-init"
}

_cli_print_help ()
{
  local label=$1 pre=$2 help=$3

  if [[ "$pre" == "--"  ]];then
    pre="  "
  fi

  if [ ${#label} -eq 0 ] ; then
    return
  elif [ ${#help} -eq 0 ] ; then
    echo -ne "\n$pre $label"
  elif [ ${#label} -lt 5 ] ; then
    echo -ne "\n$pre $label\t\t\t$help"
  elif [ ${#label} -lt 13 ] ; then
    echo -ne "\n$pre $label\t\t$help"
  else
    echo -ne "\n$pre $label\t$help"
  fi
}

_cli_help ()
{
  local cur=$1;
  shift

  echo -en "\nPossible completions:"
  for comp; do
    _cli_print_help "${comp}" "${_cli_array_pre[${comp}]}" "${_cli_array_helps[${comp}]}"
  done
}

_cli_help_mode ()
{
  local mode=$1
  shift
  local mode_str=$1;
  shift

  if [[ ${mode} = 1 ]];then
     echo -en "\n${mode_str} commands:"
  fi
  for comp; do
    _cli_print_help "${comp}" "${_cli_array_pre[${comp}]}" "${_cli_array_helps[${comp}]}"
  done
}

# Render the "?" / possible-completions help through the pager so a help
# list taller than the terminal doesn't scroll off the top of the screen.
# CLI_PAGER already carries `less --quit-if-one-screen`, so help that fits
# on one screen is printed inline and less exits immediately (identical to
# the previous direct echo); only over-long help enters interactive paging.
# This runs inside the readline completion callback: less reads keystrokes
# from /dev/tty and writes to the callback's stdout (the terminal), then
# readline redraws the prompt with the typed input restored. In a
# non-interactive shell CLI_PAGER is `cat`, so this stays a plain dump.
_cli_page_help ()
{
  _cli_help_mode "$@" | ${CLI_PAGER}
}

get_prefix_filtered_list ()
{
  # $1: prefix
  # $2: \@list
  # $3: \@filtered
  declare -a olist
  local pfx=$1
  pfx=${pfx#\"}
  eval "olist=( \"\${$2[@]}\" )"
  local idx=0
  for elem in "${olist[@]}"; do
    local sub=${elem#$pfx}
    if [[ "$elem" == "$sub" ]] && [[ -n "$pfx" ]]; then
      continue
    fi
    eval "$3[$idx]=\"$elem\""
    (( idx++ ))
  done
}

_cli_set_completions ()
{
  local current=$1
  local col

  _cli_array_completions=()
  completions=()
  completions2=()
  OIFS=${IFS}

  # Quiet when the daemon cannot be reached: a warning printed here
  # would land in the middle of the line being completed.
  if [[ -z "$current" ]];then
    IFS='' input=$(${cli_command} -t -m ${CLI_MODE} -- ${COMP_WORDS[@]} 2>/dev/null)
  else
    IFS='' input=$(${cli_command} -c -m ${CLI_MODE} -- ${COMP_WORDS[@]} 2>/dev/null)
  fi
  declare -i first=1
  while read line; do
    if [[ ${first} -eq 1 ]];then
      ret=${line}
      first=0
    else
      IFS=$'\t' col=(${line})
      completions=(${completions[@]} ${col[0]})
      # Everything except a type-hint placeholder is a literal,
      # TAB-completable word. Placeholders (`<name:string>`,
      # `<A.B.C.D>`, `<cr>`, ...) all start with '<' and must be kept
      # out of the compgen word list. A previous initial-character
      # whitelist (`[a-zEH0-9/]`) wrongly dropped any candidate whose
      # first character was an uppercase letter other than E/H, so a
      # VRF/interface/neighbour name like `N6` showed under `?` but
      # never expanded on TAB.
      if [[ ${col[0]} != "<"* ]];then
        completions2=(${completions2[@]} ${col[0]})
        _cli_array_completions=(${_cli_array_completions[@]} ${col[0]})
      fi
      _cli_array_pre[${col[0]}]=${col[1]}
      _cli_array_helps[${col[0]}]=${col[2]}
    fi
  done <<<${input}
  IFS=${OIFS}

  if [ -n "${current}" ];then
    _cli_array_completions=()
    get_prefix_filtered_list "$cur" completions2 _cli_array_completions
  fi
}

_cli_completion ()
{
  # Retry first-level registration if it never succeeded (daemon was
  # down at startup). Doing it here means TAB on an empty line or any
  # partial command transparently recovers once the daemon is up.
  _cli_maybe_register

  compopt -o nospace

  local restore_shopts=$(shopt -p extglob nullglob | tr \\n \;)
  shopt -s extglob nullglob
  local current=""
  local current_prefix=$2
  local current_word=$3
  local current_empty=0

  if (( ${COMP_CWORD} < 0 ));then
    current_empty=1
  fi

  if (( ${#COMP_WORDS[@]} > 0 )); then
    current=${COMP_WORDS[COMP_CWORD]}
  else
    (( COMP_CWORD = ${#COMP_WORDS[@]} ))
  fi

  if [[ -z "$current_word" ]]; then
    _cli_set_completions $current
  else
    _cli_set_completions $current_prefix
  fi

  if [[ "$COMP_KEY" -eq 63 ]];then
    _cli_page_help ${current_empty} "${CLI_MODE_STR}" "${completions[@]}"
    COMPREPLY=("" " ")
  else
    COMPREPLY=($(compgen -W "${_cli_array_completions[*]}" -- $current_prefix))

    # Append space to completion word.
    if [[ ${#COMPREPLY[@]} -eq 1 ]];then
      COMPREPLY=( "${COMPREPLY[0]} " )
    else
      if [[ ${#COMP_WORDS[@]} -eq 0 ]];then
        _cli_page_help ${current_empty} "${CLI_MODE_STR}" "${_cli_array_completions[@]}"
        COMPREPLY=("" " ")
      fi
    fi
  fi

  eval "$restore_shopts"
}

_cli_exec ()
{
  declare -i first=1
  local -i rc entered=0
  # The mode the command runs in: the USR1 trap may change CLI_MODE
  # while it does.
  local mode=${CLI_MODE}

  if [[ ${CLI_FORMAT} == "json" ]];then
    JSON_FLAG="-j"
  else
    JSON_FLAG=""
  fi

  OIFS=${IFS}
  # vtyhelper's stderr is not captured: when the daemon cannot be
  # reached, its one-line warning is what the operator sees. `--` keeps
  # the operator's words theirs: `description -a` is not a helper option.
  IFS='' input=$(${cli_command} ${JSON_FLAG} -m ${mode} -- $@)
  rc=$?
  IFS=${OIFS}
  while read line; do
    if [[ ${first} -eq 1 ]];then
      result=${line}
      first=0
      case ${result} in
        "Show")
          while IFS= read line; do
            echo "$line"
          done | ${CLI_PAGER}
          ;;
      esac
    else
      break
    fi
  done <<<${input}
  IFS=${OIFS}

  case ${result} in
    "NoMatch")
      echo "% No such command: $*" ;;
    "Ambiguous")
      echo "% Ambiguous command: $*" ;;
    "Incomplete")
      echo "% Incomplete command." ;;
    "SuccessExec")
      if [[ "${line}" == "exit" ]];then
        exit
      else
        eval "$line"
        # Note the entry into configure mode here rather than in the
        # `configure` shell function: keying off the mode the daemon
        # just handed us catches every path in.
        if [[ ${CLI_MODE} == "configure" ]]; then
          _cli_entered_configure=1
          entered=1
        fi
      fi ;;
  esac

  # Refused for want of the admin role.
  if (( rc == 4 )); then
    if [[ ${mode} == "configure" ]]; then
      # The role lapsed, or the daemon restarted and forgot it. Only
      # `exit` and `help` run without it, so leave configure mode. In a
      # pipeline this runs in a subshell, which cannot change the shell's
      # mode; the shell's USR1 trap does. The trap may also have left
      # configure mode already, while the command ran.
      if (( BASHPID != $$ )); then
        [[ ${interactive} ]] && kill -USR1 $$ 2>/dev/null
      elif [[ ${CLI_MODE} == "configure" ]]; then
        _cli_admin_lapsed
        _cli_notice_flush
      fi
    elif [[ ${EUID} -ne 0 && -z ${_cli_retrying} ]] && (( BASHPID == $$ )); then
      # In exec mode only entering configure mode is gated, whether
      # typed whole or abbreviated (`conf`): take the role, then try
      # again, once.
      _cli_take_admin || return 1
      local _cli_retrying=1
      _cli_exec "$@"
      return
    else
      echo "% Configuration access denied"
    fi
  fi

  # A committed `set/delete system hostname` (possibly by another
  # session) must show on the next prompt; config commands come back
  # as silent Show replies with nothing eval-able, so re-ask the
  # daemon after every executed command.
  _cli_hostname_refresh
  # The admin role that entering configure mode needed is watched from
  # here on, so that the shell leaves configure mode when it lapses. The
  # refresh has just said how long it has.
  (( entered )) && _cli_admin_watch "${_cli_admin_secs}"
  return ${rc}
}

# Sync CLI_HOSTNAME (and the prompt) with the daemon's running-config
# `system hostname`, and note in _cli_admin_secs how long the admin role
# has left: one question (`vtyhelper -S`) for both. A failed query
# (daemon down) leaves the host name untouched.
_cli_hostname_refresh ()
{
  local out name secs
  local -i rc
  _cli_admin_secs=""
  out=$(${cli_command} -S 2>/dev/null)
  rc=$?
  # 2: a vtyhelper from before -S (a vty rebuilt, the helper not
  # reinstalled), whose option parser refuses it. The host name alone.
  if (( rc == 2 )); then
    out=$(${cli_command} -H 2>/dev/null)
    rc=$?
  fi
  (( rc == 0 )) || return 0
  { IFS= read -r name; IFS= read -r secs; } <<<"${out}"
  [[ ${secs} =~ ^-?[0-9]+$ ]] && _cli_admin_secs=${secs}
  if [[ ${name} != "${CLI_HOSTNAME}" ]]; then
    CLI_HOSTNAME=${name}
    _cli_prompt_setup
  fi
}

# bash calls this when a typed word matches no alias / function /
# builtin / PATH executable. If first-level registration never
# succeeded (daemon was down at startup), retry it now and — if the
# typed word turns out to be a freshly-registered first-level command
# — dispatch it through _cli_exec so the user doesn't have to retype.
command_not_found_handle ()
{
  if (( _cli_first_level_registered == 0 )); then
    _cli_register_first_level_command loud
    if (( _cli_first_level_registered == 1 )) && alias "$1" >/dev/null 2>&1; then
      _cli_exec "$@"
      return $?
    fi
    # Not "command not found": with the daemon out of reach, the word
    # may well be one of its commands.
    if [[ -n ${_cli_unreachable_msg} ]]; then
      printf '%s\n' "${_cli_unreachable_msg}" >&2
      return 127
    fi
  fi
  echo "$1: command not found" >&2
  return 127
}

_cli_register_first_level_command ()
{
  shopt -s expand_aliases
  unalias -a
  OOIFS=${IFS}
  # Only the command list is read: it is eval'ed into aliases below, so
  # nothing else may reach it. $1 `loud` (startup, a typed command) also
  # asks again, when the daemon cannot be reached, for the warning that
  # those callers print; completion retries this on every TAB and stays
  # at one attempt.
  IFS=''  input=$(${cli_command} -f -m ${CLI_MODE} 2>/dev/null)
  local -i rc=$?
  _cli_unreachable_msg=""
  if (( rc != 0 )); then
    input=""
    if (( rc == 3 )) && [[ $1 == "loud" ]]; then
      _cli_unreachable_msg=$(${cli_command} -f -m ${CLI_MODE} 2>&1 >/dev/null)
    fi
  fi
  local -i registered=0
  while read cmd; do
    [[ -z "${cmd}" ]] && continue
    IFS='' seq_input=$(seq 1 ${#cmd})
    while read pos; do
      complete -F _cli_completion ${cmd:0:$pos}
      eval alias ${cmd:0:$pos}=\'_cli_exec ${cmd:0:$pos}\'
    done <<<${seq_input}
    (( registered++ ))
  done <<<${input}
  IFS=${OOIFS}
  if (( registered > 0 )); then
    _cli_first_level_registered=1
    [[ ${CLI_MODE} == "exec" ]] && _cli_register_configure_only_commands
  else
    _cli_first_level_registered=0
  fi
  # `enable`, `disable` and `configure` are shell functions below: they
  # read the password without echo and take the admin role before
  # configure mode. The daemon's aliases for those names must not shadow
  # them after any registration, not just the first, or a `configure`
  # typed after leaving configure mode would skip taking the role.
  unalias enable disable configure 2>/dev/null
  return ${rc}
}

# Configure-mode commands typed in exec mode used to fall through to
# bash. `set` is a bash builtin, so `set interface ... address ...` was
# taken without a word (it set the shell's positional parameters) and
# the operator, finding nothing in running-config, could not tell why;
# `commit`, `delete` and the rest said only "command not found". Alias
# each first-level configure command that exec mode lacks to a message
# naming the mode it belongs to. Only the whole word is aliased, and
# only when exec mode has no alias for it yet: a prefix such as `s` or
# `c` may be an exec command's. `exit` stays bash's, which is how exec
# mode leaves the vty.
_cli_register_configure_only_commands ()
{
  local cmd input
  input=$(${cli_command} -f -m configure 2>/dev/null)
  while read -r cmd; do
    [[ -z ${cmd} || ${cmd} == "exit" ]] && continue
    alias "${cmd}" >/dev/null 2>&1 && continue
    alias "${cmd}=_cli_configure_only ${cmd}"
  done <<<"${input}"
}

_cli_configure_only ()
{
  # A bare `clear` still clears the screen, as in any shell; `clear
  # isis neighbor` and the like are configure-mode commands.
  if [[ $1 == "clear" && $# -eq 1 ]]; then
    command clear
    return
  fi
  echo "% '$1' is only available in configure mode; type 'configure' first."
  return 1
}

# Re-attempt first-level registration if the initial attempt at vty
# startup ran while the daemon was down. Called from the completion
# handler and the command-not-found handler so the next TAB or typed
# command picks up commands once the daemon becomes reachable.
_cli_maybe_register ()
{
  if (( _cli_first_level_registered == 0 )); then
    _cli_register_first_level_command
  fi
}

_cli_ctrl_caret ()
{
  CLI_MODE="exec"
  CLI_MODE_PROMPT=""
  CLI_MODE_STR="Exec"
  _cli_register_first_level_command
  _cli_prompt_setup
}

_cli_bind_key ()
{
  complete -E -F _cli_completion
  complete -D -F _cli_completion
  bind '"?": possible-completions'
  bind '"\C-l": clear-screen'
  bind 'set show-all-if-ambiguous on'
  stty susp ''
  bind -x '"\C-^": _cli_refresh'
  bind '"\C-z":"\C-^\C-m"'
}

_cli_refresh ()
{
  _cli_register_first_level_command
  _cli_prompt_setup
}

# The admin role lapses. The daemon gives a non-root session the role
# for 900 seconds past its last admin command (4 hours at most), then
# refuses every configure-mode command but `exit` and `help`: an
# operator left in configure mode could do nothing there. A timer
# (`vtyhelper --timer`, a child that dies with this shell) wakes the
# shell with SIGUSR1 when the role may have lapsed; the trap asks the
# daemon how long the role has left (`vtyhelper -a`, which does not
# extend it) and either waits that long again or, once the role is gone,
# goes back to exec mode with a one-line notice. Root's role never
# lapses.

# Is $1 our timer, still running? It may have exited and its pid been
# reused, by anyone. /proc/PID/stat reads "PID (COMM) STATE PPID ...",
# and COMM is whatever the process's owner named it: spaces, brackets,
# `$(...)`. So split after its last ')', and compare as text, never in
# arithmetic, which would evaluate it.
_cli_admin_timer_alive ()
{
  local stat comm state ppid
  [[ $1 =~ ^[0-9]+$ ]] || return 1
  { IFS= read -r stat; } 2>/dev/null </proc/$1/stat || return 1
  [[ ${stat} == *") "* ]] || return 1
  comm=${stat#*(}
  comm=${comm%)*}
  read -r state ppid _ <<<"${stat##*) }"
  [[ ${comm} == "vtyhelper" && ${ppid} == "$$" ]]
}

_cli_admin_timer_cancel ()
{
  _cli_admin_timer_alive "${_cli_admin_timer_pid}" \
    && kill "${_cli_admin_timer_pid}" 2>/dev/null
  _cli_admin_timer_pid=""
  return 0
}

_cli_admin_timer_arm ()
{
  _cli_admin_timer_cancel
  # The braces' redirection keeps job control's "[1] PID" off the
  # terminal, and disown keeps its "Done" off too. The timer signals
  # only this shell, named by its pid.
  { ${cli_command} --timer "$1" --parent $$ & } 2>/dev/null
  _cli_admin_timer_pid=$!
  disown "${_cli_admin_timer_pid}" 2>/dev/null
  return 0
}

# Wait for the role's time, $1 seconds: noted, so that a lapse can be
# told from a role taken away.
_cli_admin_timer_arm_role ()
{
  _cli_admin_timer_arm "$1"
  _cli_admin_deadline=$(( SECONDS + $1 ))
}

# How long the session's admin role has left, asked of the daemon
# (`vtyhelper -a`, which does not extend it), into _cli_admin_secs.
# Status 0 when it answered; 5 when it cannot (a daemon from before the
# question); anything else when it could not be asked now (3
# unreachable, 1 another failure).
_cli_admin_left ()
{
  local out
  local -i rc
  _cli_admin_secs=""
  out=$(${cli_command} -a 2>/dev/null)
  rc=$?
  if (( rc == 0 )) && [[ ${out} =~ ^-?[0-9]+$ ]]; then
    _cli_admin_secs=${out}
    return 0
  fi
  (( rc == 0 )) && return 1
  return ${rc}
}

# Watch the admin role the session holds, unless it cannot lapse or a
# timer already runs (it asks again when it goes off). $1, when given,
# is how long the role has left, just learnt; otherwise ask.
_cli_admin_watch ()
{
  [[ ${interactive} ]] || return 0
  [[ ${EUID} -eq 0 ]] && return 0
  _cli_admin_timer_alive "${_cli_admin_timer_pid}" && return 0
  if [[ $1 =~ ^-?[0-9]+$ ]]; then
    _cli_admin_secs=$1
  else
    _cli_admin_left
    case $? in
      0) ;;
      # It cannot say: nothing to watch by.
      5) return 0 ;;
      # It could not be asked now: ask again later.
      *) _cli_admin_timer_arm "${_cli_admin_retry}"; return 0 ;;
    esac
  fi
  (( _cli_admin_secs > 0 )) && _cli_admin_timer_arm_role "${_cli_admin_secs}"
  return 0
}

# Ask the daemon how long the admin role has left and act on it: wait
# again, or, once the role is gone, leave configure mode and the `#`
# prompt. The USR1 trap: the timer went off, or a refused command in a
# pipeline sent it.
_cli_admin_check ()
{
  # Exec mode without the admin prompt has nothing to leave.
  if [[ ${CLI_MODE} != "configure" ]] && (( CLI_PRIVILEGE < 15 )); then
    _cli_admin_timer_cancel
    return 0
  fi
  _cli_admin_left
  case $? in
    0) ;;
    # It cannot say: nothing to go by.
    5) _cli_admin_timer_cancel; return 0 ;;
    # It could not be asked now (restarting, unreachable): ask again
    # later.
    *) _cli_admin_timer_arm "${_cli_admin_retry}"; return 0 ;;
  esac
  if (( _cli_admin_secs > 0 )); then
    _cli_admin_timer_arm_role "${_cli_admin_secs}"
  elif (( _cli_admin_secs == 0 )); then
    _cli_admin_lapsed
  else
    _cli_admin_timer_cancel
  fi
  return 0
}

# The admin role is gone: leave configure mode, where only `exit` and
# `help` run without it, and leave the operator a notice. It timed out
# when the time the timer waited for has passed; otherwise it was taken
# (a daemon restart, say), and the notice must not blame the clock.
_cli_admin_lapsed ()
{
  local -i timed_out=0
  (( _cli_admin_deadline > 0 && SECONDS + 1 >= _cli_admin_deadline )) && timed_out=1
  _cli_admin_timer_cancel
  _cli_admin_secs=0
  _cli_admin_deadline=0
  if [[ ${CLI_MODE} == "configure" ]]; then
    CLI_PRIVILEGE=1
    _cli_ctrl_caret
    if (( timed_out )); then
      _cli_notice="% Configuration session timed out; back to exec mode."
    else
      _cli_notice="% Admin role no longer held; back to exec mode."
    fi
  elif (( CLI_PRIVILEGE >= 15 )); then
    CLI_PRIVILEGE=1
    _cli_prompt_setup
    if (( timed_out )); then
      _cli_notice="% Admin role timed out."
    else
      _cli_notice="% Admin role no longer held."
    fi
  fi
  return 0
}

# PROMPT_COMMAND: print a notice a trap left while no input was being
# read (the vty prints one left during input itself).
_cli_notice_flush ()
{
  [[ -n ${_cli_notice} ]] || return 0
  printf '%s\n' "${_cli_notice}"
  _cli_notice=""
}

# Ask the daemon for the admin role: root and zebra-rs group members
# without a password, everyone else with the root password, read here
# without echo. The status is vtyhelper's: 0 granted, 3 unreachable.
# When granted, the reply's "% Enabled (admin role active for N
# seconds)" is how long the role has, noted for the timer.
_cli_enable_rpc ()
{
  local out
  local -i rc
  _cli_admin_secs=""
  # A timer going off in the middle of the password prompt would cut it
  # short; the callers watch the role again afterwards.
  _cli_admin_timer_cancel
  if [[ ${EUID} -eq 0 ]] || _cli_in_config_group; then
    out=$(${cli_command} -e -m ${CLI_MODE})
    rc=$?
  else
    local pw
    if [[ -t 0 ]]; then
      stty -echo
      read -r -p "Root password: " pw
      stty echo
      echo
    else
      IFS= read -r pw
    fi
    out=$(CLI_ENABLE_PASSWORD="${pw}" ${cli_command} -e -m ${CLI_MODE})
    rc=$?
    pw=""
    unset pw
  fi
  [[ -n ${out} ]] && printf '%s\n' "${out}"
  if (( rc == 0 )) && [[ ${out} =~ active\ for\ ([0-9]+)\ seconds ]]; then
    _cli_admin_secs=${BASH_REMATCH[1]}
  fi
  return ${rc}
}

enable ()
{
  if [[ ${CLI_MODE} != "exec" ]]; then
    echo "% 'enable' is only available in exec mode."
    return 1
  fi
  _cli_enable_rpc
  local -i rc=$?
  if (( rc == 0 )); then
    CLI_PRIVILEGE=15
    _cli_prompt_setup
    _cli_admin_watch "${_cli_admin_secs}"
  else
    # A failed second `enable` leaves the first one's role, if any, to
    # watch; a `#` prompt whose role is gone drops.
    _cli_admin_check
  fi
  return ${rc}
}

# Take the admin role for configure mode, which then watches it.
_cli_take_admin ()
{
  _cli_enable_rpc
  local -i rc=$?
  (( rc == 0 )) && return 0
  # 3: the daemon could not be reached, and the helper has said so.
  (( rc == 3 )) || echo "% Configuration access denied"
  # The timer was stopped for the password: watch what role is left,
  # and drop a `#` prompt whose role is gone.
  _cli_admin_check
  return 1
}

# `configure` is a function so that it is told apart in configure mode;
# taking the admin role when the daemon refuses it is _cli_exec's, for
# the whole word and its abbreviations alike. No question first: the
# refusal is the answer, and a daemon from before the question gives it
# too.
configure ()
{
  if [[ ${CLI_MODE} != "exec" ]]; then
    echo "% 'configure' is only available in exec mode."
    return 1
  fi
  _cli_exec configure
}

disable ()
{
  ${cli_command} -d -m ${CLI_MODE}
  local rc=$?
  if [[ ${rc} -eq 0 ]]; then
    _cli_admin_timer_cancel
    _cli_admin_secs=0
    _cli_admin_deadline=0
    CLI_PRIVILEGE=1
    # Configure mode without the role runs nothing but `exit` and `help`.
    if [[ ${CLI_MODE} == "configure" ]]; then
      _cli_ctrl_caret
    else
      _cli_prompt_setup
    fi
  fi
  return ${rc}
}

# Run `commit` or `discard` on the way out and report what happened.
#
# Not routed through _cli_exec: that sends -m ${CLI_MODE}, which is
# `exec` by the time we are exiting, where neither command exists. The
# explicit -m configure is admin-gated, and vtyhelper answers a denial
# by exiting 1 with no output at all — so without this wrapper a user
# who answers `y` sees nothing and keeps their uncommitted changes.
_cli_exit_config_cmd ()
{
  local out rc
  out=$(${cli_command} -m configure -- "$1" 2>&1)
  rc=$?
  # vtyhelper prints a bare `Show` marker line ahead of the reply body;
  # a successful commit/discard has nothing after it.
  out=${out#Show}
  if [[ ${rc} -eq 3 ]]; then
    # The daemon could not be reached: the helper's warning says so.
    printf '%s\n' "${out}" >&2
    echo "% ${1} not done; changes left uncommitted." >&2
  elif [[ ${rc} -ne 0 ]]; then
    echo "% ${1} failed (admin role required — run 'enable'); changes left uncommitted." >&2
  elif [[ -n ${out//[[:space:]]/} ]]; then
    # Validation errors from commit land here; the candidate is intact.
    printf '%s\n' "${out#$'\n'}" >&2
  fi
}

# Bash EXIT trap. Two jobs, in this order: offer to commit pending
# config changes, then drop the server-side session.
#
# The trap is the right seam because the answer never cancels the exit —
# it catches a typed `exit`, Ctrl-D and a closing terminal alike, where
# a shell function shadowing the `exit` builtin would miss the last two.
#
# Invariants: never call `exit` and never `set -e` in here, or the
# shell's real exit status is lost.
_cli_exit_hook ()
{
  # The timer must not cut the question below short. It dies with the
  # shell anyway; this only makes it go first.
  _cli_admin_timer_cancel

  # Gate before the RPC: nothing to ask a shell that never configured.
  # -t 2 matters as much as -t 0 — `read -p` writes the prompt to
  # stderr, so with stderr redirected the user would face an invisible
  # question; and with no tty at all bash drops the prompt silently and
  # blocks on a read that eats stdin.
  if [[ ${_cli_entered_configure} -eq 1 && -t 0 && -t 2 ]]; then
    # 0 = differs, 1 = identical, 2 = unknown. Ask only on a definite
    # 0, so a daemon that is down or slow never delays an exit.
    if ${cli_command} -u >/dev/null 2>&1; then
      local ans
      # The timeout is not optional. A tty reports EOF once, not
      # stickily, so after a Ctrl-D exit this read blocks forever on a
      # shell that has already decided to die — and further Ctrl-D
      # cannot break it. CLI_EXIT_PROMPT_TIMEOUT exists so the tests
      # don't have to wait out the default.
      # Kept to 70 columns so an 80-column terminal has room for the
      # answer instead of wrapping the question.
      read -t "${CLI_EXIT_PROMPT_TIMEOUT:-30}" -r -p \
        "You have uncommitted changes. Commit? [y=commit n=discard other=keep] " ans
      if [[ $? -gt 128 ]]; then
        # Timed out: leave the candidate alone and close the prompt line.
        echo >&2
      else
        echo >&2
        case ${ans} in
          [Yy]*) _cli_exit_config_cmd commit ;;
          [Nn]*) _cli_exit_config_cmd discard ;;
        esac
      fi
    fi
  fi

  # Logout LAST. Dropping the session makes the next RPC re-resolve as
  # a fresh View session, so a commit issued after this point would be
  # refused. The kernel pidfd watcher also catches shell death; this
  # explicit RPC just shaves a moment off the cleanup for clean exits.
  ${cli_command} -l >/dev/null 2>&1 || true
}

if [[ $interactive ]]; then
  _cli_pager_setup
  _cli_bind_key
  # Seed the prompt hostname from the daemon's running config; a down
  # daemon yields an empty value and the OS-hostname fallback (the
  # next successful exec self-heals it, like _cli_maybe_register).
  CLI_HOSTNAME=$(${cli_command} -H 2>/dev/null)
  _cli_prompt_setup
  trap _cli_exit_hook EXIT
  trap _cli_admin_check USR1
  PROMPT_COMMAND="_cli_notice_flush${PROMPT_COMMAND:+;${PROMPT_COMMAND}}"
else
  CLI_PAGER="cat"
fi
_cli_register_first_level_command loud
# Say so at once when the daemon cannot be reached: until it can, no
# vty command works. (Registration is retried on the next TAB or
# command, and keeps the shell functions for enable/disable/configure
# ahead of the daemon's aliases.)
# (Not in a script: its first command says so itself, and once is
# enough.)
if [[ ${interactive} && -n ${_cli_unreachable_msg} ]]; then
  printf '%s\n' "${_cli_unreachable_msg}" >&2
fi

# Local variables:
# mode: shell-script
# sh-indentation: 2
# sh-basic-offset: 2
# End:
