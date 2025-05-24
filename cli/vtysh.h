/* vtysh.h -- Zebra shell extension for bash. */

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

#if !defined (_VTYSH_H_)
#define _VTYSH_H_

#include "stdc.h"

extern int cli_mode __P((void));
extern void cli_execute_startup_string __P((void));

#endif /* _VTYSH_H_ */
