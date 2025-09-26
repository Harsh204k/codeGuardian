user_allowed(cupsd_printer_t *p,	/* I - Printer or class */
             const char      *username)	/* I - Username */
{
  struct passwd	*pw;			/* User password data */
  char		baseuser[256],		/* Base username */
		*baseptr,		/* Pointer to "@" in base username */
		*name;			/* Current user name */


  if (cupsArrayCount(p->users) == 0)
    return (1);

  if (!strcmp(username, "root"))
    return (1);

  if (strchr(username, '@'))
  {
   /*
    * Strip @REALM for username check...
    */

    strlcpy(baseuser, username, sizeof(baseuser));

    if ((baseptr = strchr(baseuser, '@')) != NULL)
      *baseptr = '\0';

    username = baseuser;
  }

  pw = getpwnam(username);
  endpwent();

  for (name = (char *)cupsArrayFirst(p->users);
       name;
       name = (char *)cupsArrayNext(p->users))
  {
    if (name[0] == '@')
    {
     /*
      * Check group membership...
      */

      if (cupsdCheckGroup(username, pw, name + 1))
        break;
    }
    else if (name[0] == '#')
    {
     /*
      * Check UUID...
      */

      if (cupsdCheckGroup(username, pw, name))
        break;
    }
    else if (!_cups_strcasecmp(username, name))
      break;
  }

  return ((name != NULL) != p->deny_users);
}