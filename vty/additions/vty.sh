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
declare -x CLI_PRIVILEGE=1
declare -a _cli_array_completions
declare -A _cli_array_helps
declare -A _cli_array_pre

# 1 once the daemon answered with at least one first-level command,
# 0 otherwise. Used to retry registration on the next TAB / command
# when vty started while the zebra-rs daemon was still down.
declare -i _cli_first_level_registered=0

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
  # `host#` in exec mode (where CLI_MODE_PROMPT is empty).
  export PS1="$(hostname)${CLI_MODE_CHAR}${CLI_MODE_PROMPT}"
}

_cli_pager_setup ()
{
  [[ -z ${CLI_PAGER} ]] && \
    CLI_PAGER="less \
      --no-lessopen\
      --quit-at-eof\
      --quit-if-one-screen\
      --raw-control-chars\
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

  if [[ -z "$current" ]];then
    IFS='' input=$(${cli_command} -t -m ${CLI_MODE} ${COMP_WORDS[@]})
  else
    IFS='' input=$(${cli_command} -c -m ${CLI_MODE} ${COMP_WORDS[@]})
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
    _cli_help_mode ${current_empty} "${CLI_MODE_STR}" "${completions[@]}"
    COMPREPLY=("" " ")
  else
    COMPREPLY=($(compgen -W "${_cli_array_completions[*]}" -- $current_prefix))

    # Append space to completion word.
    if [[ ${#COMPREPLY[@]} -eq 1 ]];then
      COMPREPLY=( "${COMPREPLY[0]} " )
    else
      if [[ ${#COMP_WORDS[@]} -eq 0 ]];then
        _cli_help_mode ${current_empty} "${CLI_MODE_STR}" "${_cli_array_completions[@]}"
        COMPREPLY=("" " ")
      fi
    fi
  fi

  eval "$restore_shopts"
}

_cli_exec ()
{
  declare -i first=1

  if [[ ${CLI_FORMAT} == "json" ]];then
    JSON_FLAG="-j"
  else
    JSON_FLAG=""
  fi

  OIFS=${IFS}
  IFS='' input=$(${cli_command} ${JSON_FLAG} -m ${CLI_MODE} $@)
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
      fi ;;
  esac
}

# bash calls this when a typed word matches no alias / function /
# builtin / PATH executable. If first-level registration never
# succeeded (daemon was down at startup), retry it now and — if the
# typed word turns out to be a freshly-registered first-level command
# — dispatch it through _cli_exec so the user doesn't have to retype.
command_not_found_handle ()
{
  if (( _cli_first_level_registered == 0 )); then
    _cli_register_first_level_command
    if (( _cli_first_level_registered == 1 )) && alias "$1" >/dev/null 2>&1; then
      _cli_exec "$@"
      return $?
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
  IFS=''  input=$(${cli_command} -f -m ${CLI_MODE})
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
  else
    _cli_first_level_registered=0
  fi
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

enable ()
{
  if [[ ${CLI_MODE} != "exec" ]]; then
    echo "% 'enable' is only available in exec mode."
    return 1
  fi
  local pw
  if [[ -t 0 ]]; then
    stty -echo
    read -r -p "Password: " pw
    stty echo
    echo
  else
    # Non-interactive: read a single password line from stdin.
    IFS= read -r pw
  fi
  CLI_ENABLE_PASSWORD="${pw}" ${cli_command} -e -m ${CLI_MODE}
  local rc=$?
  pw=""
  unset pw
  if [[ ${rc} -eq 0 ]]; then
    CLI_PRIVILEGE=15
    _cli_prompt_setup
  fi
  return ${rc}
}

# `configure` with auto-elevate (D24): when the caller is not already
# admin (root / service-account / prior `enable`), prompt for a
# password and run a PAM authentication against the caller's own
# account (sudo-style) before entering configure mode. The same
# password that works for `enable` works here.
configure ()
{
  if [[ ${CLI_MODE} != "exec" ]]; then
    echo "% 'configure' is only available in exec mode."
    return 1
  fi

  # Fast path: if the caller already enabled (CLI_PRIVILEGE >= 15),
  # skip the auto-elevate probe entirely. enable() sets
  # CLI_PRIVILEGE=15 on success, so this avoids re-prompting an
  # already-authenticated operator under any circumstance.
  if (( CLI_PRIVILEGE < 15 )); then
    # Optimistic first attempt — root / service-account sessions
    # succeed immediately without any prompt.
    local out first_line
    out=$(${cli_command} -m exec configure 2>&1)
    first_line=$(echo "$out" | head -n 1)
    if [[ "${first_line}" != "SuccessExec" ]]; then
      # Permission denied (or other error). Prompt for the root
      # password and elevate via PAM.
      local pw
      if [[ -t 0 ]]; then
        stty -echo
        read -r -p "Password: " pw
        stty echo
        echo
      else
        IFS= read -r pw
      fi
      CLI_ENABLE_PASSWORD="${pw}" ${cli_command} -e -m ${CLI_MODE}
      local rc=$?
      pw=""
      unset pw
      if [[ ${rc} -ne 0 ]]; then
        echo "% Configuration access denied"
        return 1
      fi
    fi
  fi

  # Either we were already admin, the optimistic attempt succeeded,
  # or we just elevated. Run the command for real via the standard
  # exec path so the daemon's SuccessExec script flips CLI_MODE etc.
  _cli_exec configure
  CLI_PRIVILEGE=15
  _cli_prompt_setup
}

disable ()
{
  ${cli_command} -d -m ${CLI_MODE}
  local rc=$?
  if [[ ${rc} -eq 0 ]]; then
    CLI_PRIVILEGE=1
    _cli_prompt_setup
  fi
  return ${rc}
}

if [[ $interactive ]]; then
  _cli_pager_setup
  _cli_bind_key
  _cli_prompt_setup
  # Tell the daemon to drop our session as soon as the shell exits.
  # The kernel pidfd watcher also catches this case; the explicit
  # logout RPC just shaves a moment off the cleanup for clean exits.
  trap '${cli_command} -l >/dev/null 2>&1 || true' EXIT
else
  CLI_PAGER="cat"
fi
_cli_register_first_level_command
# If the daemon registers 'enable'/'disable'/'configure' as
# first-level commands, strip the aliases so our shell functions
# above take precedence — they need to read the password locally
# with stty -echo and/or run an auto-elevate flow that the plain
# _cli_exec path cannot handle.
unalias enable 2>/dev/null || true
unalias disable 2>/dev/null || true
unalias configure 2>/dev/null || true

# Local variables:
# mode: shell-script
# sh-indentation: 2
# sh-basic-offset: 2
# End:
