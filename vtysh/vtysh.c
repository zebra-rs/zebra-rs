/* vtysh.c -- zebra shell extension for bash. */

/* Copyright (C) 2024 Zebra Project.

   This file is part of GNU Bash, the Bourne Again SHell.

   Bash is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   Bash is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Bash.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "config.h"
#include <stdlib.h>

#include "vtysh.h"
#include "shell.h"

#include "builtins.h"
#include "builtins/common.h"
#include "bashhist.h"

/* xxd -i cli.sh >cli.c */
#include "cli.c"

int
cli_mode ()
{
  if (getenv("CLI_MODE"))
    return 1;
  else
    return 0;
}

void
cli_execute_startup_string()
{
  char *str = malloc(cli_sh_len + 1);
  memcpy(str, cli_sh, cli_sh_len);
  str[cli_sh_len] = '\0';

  enable_history_list = 0;
  bash_history_disable();

  evalstring(str, NULL, 0);

  bash_history_enable();
  enable_history_list = 1;
}
