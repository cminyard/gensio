/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <string.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_osops_env.h>
#include <gensio/argvutils.h>

#ifdef _WIN32

#include <windows.h>

int
gensio_os_env_get(const char *name, char *rval, gensiods *len)
{
    DWORD rv;
    gensiods olen = *len;

    rv = GetEnvironmentVariable(name, rval, olen);
    if (rv == 0) {
	if (GetLastError() == ERROR_ENVVAR_NOT_FOUND)
	    return GE_NOTFOUND;
	return GE_INVAL;
    }
    if (rv >= olen) {
	/*
	 * Windows returns the length with the nil char included on not
	 * big enough.  We return without the nil char for consistency.
	 */
	*len = rv - 1;
	return GE_TOOBIG;
    }
    *len = rv;
    return 0;
}

int
gensio_os_env_set(const char *name, const char *val)
{
    if (!SetEnvironmentVariable(name, val))
	return GE_INVAL;
    return 0;
}

int
gensio_os_argvenv_alloc(struct gensio_os_funcs *o,
			const char ***rargv, gensiods *rargs, gensiods *rargc)
{
    char *epos = GetEnvironmentStrings(), *spos = epos;
    const char **argv = NULL;
    gensiods args = 0, argc = 0;
    int rv = 0;

    while (*spos) {
	rv = gensio_argv_append(o, &argv, spos, &args, &argc, true);
	if (rv)
	    break;
	spos += strlen(spos) + 1;
    }
    FreeEnvironmentStrings(epos);
    if (!rv)
	rv = gensio_argv_append(o, &argv, NULL, &args, &argc, true);

    if (rv && argv)
	gensio_argv_free(o, argv);
    if (!rv) {
	*rargv = argv;
	*rargs = args;
	*rargc = argc;
    }
    return rv;
}

#else /* _WIN32 */

#include <stdlib.h>
#include <errno.h>

int
gensio_os_env_get(const char *name, char *rval, gensiods *len)
{
    const char *tval = getenv(name);
    gensiods olen = *len;

    if (!tval)
	return GE_NOTFOUND;
    *len = strlen(tval);
    if (*len + 1 > olen)
	return GE_TOOBIG;
    memcpy(rval, tval, *len + 1);
    return 0;
}

int
gensio_os_env_set(const char *name, const char *val)
{
    if (val) {
	if (setenv(name, val, true) != 0) {
	    if (errno == ENOMEM)
		return GE_NOMEM;
	    return GE_INVAL;
	}
    } else {
	if (unsetenv(name) != 0)
	    return GE_INVAL;
    }
    return 0;
}

extern char **environ;

int
gensio_os_argvenv_alloc(struct gensio_os_funcs *o,
			const char ***rargv, gensiods *rargs, gensiods *rargc)
{
    char **epos;
    const char **argv = NULL;
    gensiods args = 0, argc = 0;
    int rv = 0;

    for (epos = environ; *epos != NULL; epos++)
	rv = gensio_argv_append(o, &argv, *epos, &args, &argc, true);
    if (!rv)
	rv = gensio_argv_append(o, &argv, NULL, &args, &argc, true);
    if (rv && argv)
	gensio_argv_free(o, argv);
    if (!rv) {
	*rargv = argv;
	*rargs = args;
	*rargc = argc;
    }
    return rv;
}

#endif /* _WIN32 */

int
gensio_os_env_getalloc(struct gensio_os_funcs *o,
		       const char *name, char **rval)
{
    gensiods len = 0;
    char dummy[1];
    char *val = dummy;
    int rv;

    rv = gensio_os_env_get(name, val, &len);
    if (rv != GE_TOOBIG)
	return rv;
    len++;
    val = o->zalloc(o, len);
    rv = gensio_os_env_get(name, val, &len);
    if (rv) {
	o->free(o, val);
	return rv;
    }
    *rval = val;
    return 0;
}

static bool
argvenv_find(const char **argv, const char *name, gensiods *pos,
	     const char **val)
{
    gensiods i, len = strlen(name);

    for (i = 0; argv[i]; i++) {
	if (strncmp(argv[i], name, len) == 0 && argv[i][len] == '=') {
	    if (pos)
		*pos = i;
	    if (val)
		*val = argv[i] + len + 1;
	    return true;
	}
    }
    return false;
}

int
gensio_os_argvenv_get(struct gensio_os_funcs *o,
		      const char **argv,
		      const char *name, char *rval, gensiods *rlen)
{
    gensiods olen = *rlen;
    const char *val;

    if (!argvenv_find(argv, name, NULL, &val))
	return GE_NOTFOUND;
    *rlen = strlen(val);
    if (*rlen + 1 > olen)
	return GE_TOOBIG;
    memcpy(rval, val, *rlen + 1);
    return 0;
}

int
gensio_os_argvenv_set(struct gensio_os_funcs *o,
		      const char ***rargv, gensiods *args, gensiods *argc,
		      const char *name, const char *val)
{
    gensiods pos;
    const char *tval, **argv = *rargv;
    char *nval;
    bool found;

    found = argvenv_find(argv, name, &pos, &tval);
    if (!val) {
	if (!found)
	    return 0;
	o->free(o, (void *) argv[pos]);
	do {
	    argv[pos] = argv[pos + 1];
	    pos++;
	} while (argv[pos]);
	(*argc)--;
    } else {
	if (!found)
	    return gensio_argv_sappend(o, rargv, args, argc, "%s=%s",
				       name, val);
	nval = gensio_alloc_sprintf(o, "%s=%s", name, val);
	if (!nval)
	    return GE_NOMEM;
	o->free(o, (void *) argv[pos]);
	argv[pos] = nval;
    }
    return 0;
}

int
gensio_os_argvenv_getalloc(struct gensio_os_funcs *o,
			   const char **argv,
			   const char *name, char **rval)
{
    gensiods len;
    const char *val;
    char *nval;

    if (!argvenv_find(argv, name, NULL, &val))
	return GE_NOTFOUND;
    len = strlen(val) + 1;
    nval = o->zalloc(o, len);
    if (!nval)
	return GE_NOMEM;
    memcpy(nval, val, len);
    *rval = nval;
    return 0;
}
