# Copyright (C) 2025 zebra-rs project.
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

if [[ $interactive ]]; then
  if [ ! `basename "/$0"` = "cli" ];then
   return 0
  fi
fi

# CLI command tool name.
cli_command=cli-helper

declare -x CLI_MODE="exec"
declare -x CLI_MODE_STR="Exec"
declare -x CLI_MODE_PROMPT=""
declare -x CLI_PRIVILEGE=1
declare -a _cli_array_completions
declare -A _cli_array_helps
declare -A _cli_array_pre

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

  export PS1="$(hostname)${CLI_MODE_PROMPT}${CLI_MODE_CHAR}"
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
  elif [ ${#label} -lt 6 ] ; then
    echo -ne "\n$pre $label\t\t\t$help"
  elif [ ${#label} -lt 14 ] ; then
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
      if [[ ${col[0]}  =~ ^[a-z0-9/] ]];then
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

_cli_register_first_level_command ()
{
  shopt -s expand_aliases
  unalias -a
  OOIFS=${IFS}
  IFS=''  input=$(${cli_command} -f -m ${CLI_MODE})
  while read cmd; do
    IFS='' seq_input=$(seq 1 ${#cmd})
    while read pos; do
      complete -F _cli_completion ${cmd:0:$pos}
      eval alias ${cmd:0:$pos}=\'_cli_exec ${cmd:0:$pos}\'
    done <<<${seq_input}
  done <<<${input}
  IFS=${OOIFS}
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

if [[ $interactive ]]; then
  _cli_pager_setup
  _cli_bind_key
  _cli_prompt_setup
else
  CLI_PAGER="cat"
fi
_cli_register_first_level_command

# Local variables:
# mode: shell-script
# sh-indentation: 2
# sh-basic-offset: 2
# End:
