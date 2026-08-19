/* vtysh.c -- zebra shell extension for bash. */

/* Copyright (C) 2026 zebra-rs project.

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
#include <stdio.h>
#include <string.h>

#include "vtysh.h"
#include "shell.h"

#include "builtins.h"
#include "builtins/common.h"
#include "bashhist.h"

/* xxd -i vty.sh >vty.c */
#include "vty.c"

/* Endpoint URI captured from --vty-socket; exported as CLI_SERVER_URL
   just before the vty startup string runs. */
static char *cli_server_url = NULL;

int
cli_mode ()
{
  if (getenv("CLI_MODE"))
    return 1;
  else
    return 0;
}

/* Rewrite a --vty-socket value into the endpoint URI vtyhelper's
   connector accepts, or return NULL if the form is not recognized.
   The daemon's --vty-socket syntax is the contract: `unix:NAME'
   passes through verbatim — vtyhelper resolves the name the same way
   the daemon does (`/PATH' filesystem, `@NAME' explicitly abstract,
   bare NAME abstract) — and `tcp:HOST:PORT' is rewritten to the
   client's tcp://HOST:PORT.  Full client URIs (tcp://, http://,
   https://) pass through unchanged. */
static char *
cli_vty_socket_uri (const char *value)
{
  char *uri;

  if (strncmp (value, "unix:", 5) == 0)
    {
      if (value[5] == '\0')
	return NULL;
      uri = malloc (strlen (value) + 1);
      if (uri)
	strcpy (uri, value);
      return uri;
    }
  if (strncmp (value, "tcp://", 6) == 0
      || strncmp (value, "http://", 7) == 0
      || strncmp (value, "https://", 8) == 0)
    {
      uri = malloc (strlen (value) + 1);
      if (uri)
	strcpy (uri, value);
      return uri;
    }
  if (strncmp (value, "tcp:", 4) == 0)
    {
      const char *hostport = value + 4;

      if (*hostport == '\0')
	return NULL;
      uri = malloc (strlen (hostport) + sizeof ("tcp://"));
      if (uri)
	sprintf (uri, "tcp://%s", hostport);
      return uri;
    }
  return NULL;
}

/* Consume `--vty-socket URI' / `--vty-socket=URI' from the leading
   option block of ARGV before bash's own long-option parsing, which
   would reject it as an invalid option.  The value is remembered and
   exported as CLI_SERVER_URL when the vty startup string runs; a
   plain setenv() here would be lost, because bash builds its variable
   table from the environ array it captured before setenv() could
   reallocate it.  Returns the new ARGC. */
int
cli_option_parse (int argc, char **argv)
{
  int i, consumed;
  const char *value;
  char *uri;

  for (i = 1; i < argc; i++)
    {
      char *arg = argv[i];

      /* The option block ends where bash's would: at `--' or the
	 first word that is not an option. */
      if (arg[0] != '-' && arg[0] != '+')
	break;
      if (strcmp (arg, "--") == 0)
	break;

      if (strcmp (arg, "--vty-socket") == 0)
	{
	  if (i + 1 >= argc)
	    {
	      fprintf (stderr, "%s: --vty-socket: option requires an argument\n",
		       argv[0]);
	      exit (2);
	    }
	  value = argv[i + 1];
	  consumed = 2;
	}
      else if (strncmp (arg, "--vty-socket=", 13) == 0)
	{
	  value = arg + 13;
	  consumed = 1;
	}
      else
	continue;

      uri = cli_vty_socket_uri (value);
      if (uri == NULL)
	{
	  fprintf (stderr,
		   "%s: --vty-socket: expected unix:NAME or tcp:HOST:PORT, got `%s'\n",
		   argv[0], value);
	  exit (2);
	}
      free (cli_server_url);
      cli_server_url = uri;

      /* Shift the consumed words (and the terminating NULL) out. */
      memmove (argv + i, argv + i + consumed,
	       (argc - i - consumed + 1) * sizeof (char *));
      argc -= consumed;
      i--;
    }
  return argc;
}

void
cli_execute_startup_string()
{
  char *str;

  /* --vty-socket wins over an inherited CLI_SERVER_URL. */
  if (cli_server_url)
    {
      SHELL_VAR *var = bind_variable ("CLI_SERVER_URL", cli_server_url, 0);
      if (var)
	set_auto_export (var);
    }

  str = malloc(vty_sh_len + 1);
  memcpy(str, vty_sh, vty_sh_len);
  str[vty_sh_len] = '\0';

  enable_history_list = 0;
  bash_history_disable();

  evalstring(str, NULL, 0);

  bash_history_enable();
  enable_history_list = 1;
}
