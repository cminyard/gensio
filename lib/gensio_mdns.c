/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This code is for discovering gensio parameters via MDNS then
 * creating a gensio based upon those..
 */

#include "config.h"
#include <gensio/gensio_err.h>

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "config.h"
#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_mdns.h>
#include <gensio/argvutils.h>

enum mdnsn_state {
    MDNSN_CLOSED,
    MDNSN_IN_OPEN_QUERY,
    MDNSN_IN_CHILD_OPEN,
    MDNSN_OPEN,
    MDNSN_IN_OPEN_ERR,
    MDNSN_IN_CLOSE,
};

struct mdnsn_data {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;

    unsigned int refcount;
    enum mdnsn_state state;

    struct gensio *io;
    struct gensio *child;

    bool nostack;
    int interface;
    int nettype;
    char *name;
    char *type;
    char *domain;
    char *host;

    bool mdns_in_free;
    struct gensio_mdns *mdns;
    struct gensio_mdns_watch *watch;

    char *laddr;
    gensiods max_read_size;
    bool readbuf_set;
    bool nodelay;
    bool nodelay_set;

    int open_err;
    gensio_done_err open_done;
    void *open_data;

    gensio_done close_done;
    void *close_data;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;
};

static void mdnsn_start_deferred_op(struct mdnsn_data *ndata);

static void
mdnsn_finish_free(struct mdnsn_data *ndata)
{
    struct gensio_os_funcs *o = ndata->o;

    if (ndata->io)
	gensio_data_free(ndata->io);
    if (ndata->laddr)
	o->free(o, ndata->laddr);
    if (ndata->name)
	o->free(o, ndata->name);
    if (ndata->type)
	o->free(o, ndata->type);
    if (ndata->domain)
	o->free(o, ndata->domain);
    if (ndata->host)
	o->free(o, ndata->host);
    if (ndata->deferred_op_runner)
	o->free_runner(ndata->deferred_op_runner);
    if (ndata->lock)
	o->free_lock(ndata->lock);
    o->free(o, ndata);
}

static void
mdnsn_lock(struct mdnsn_data *ndata)
{
    ndata->o->lock(ndata->lock);
}

static void
mdnsn_unlock(struct mdnsn_data *ndata)
{
    ndata->o->unlock(ndata->lock);
}

static void
mdnsn_ref(struct mdnsn_data *ndata)
{
    assert(ndata->refcount > 0);
    ndata->refcount++;
}

static void
mdnsn_deref_and_unlock(struct mdnsn_data *ndata)
{
    assert(ndata->refcount > 0);
    if (ndata->refcount == 1) {
	mdnsn_unlock(ndata);
	mdnsn_finish_free(ndata);
    } else {
	ndata->refcount--;
	mdnsn_unlock(ndata);
    }
}

static int
child_cb(struct gensio *io, void *user_data,
	 int event, int err,
	 unsigned char *buf, gensiods *buflen,
	 const char *const *auxdata)
{
    struct mdnsn_data *ndata = user_data;

    return gensio_cb(ndata->io, event, err, buf, buflen, auxdata);
}

static void
mdnsn_check_close(struct mdnsn_data *ndata)
{
    if (!ndata->child && !ndata->mdns_in_free) {
	ndata->state = MDNSN_CLOSED;
	mdnsn_unlock(ndata);

	if (ndata->close_done)
	    ndata->close_done(ndata->io, ndata->close_data);

	mdnsn_lock(ndata);
    }
}

static void
mdnsn_deferred_op(struct gensio_runner *runner, void *cb_data)
{
    struct mdnsn_data *ndata = cb_data;

    mdnsn_lock(ndata);
    if (ndata->state == MDNSN_IN_CLOSE)
	mdnsn_check_close(ndata);

    ndata->deferred_op_pending = false;
    mdnsn_deref_and_unlock(ndata);
}

static void
mdnsn_start_deferred_op(struct mdnsn_data *ndata)
{
    if (!ndata->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	ndata->deferred_op_pending = true;
	ndata->o->run(ndata->deferred_op_runner);
	mdnsn_ref(ndata);
    }
}

static void
i_child_open_cb(struct mdnsn_data *ndata, int err)
{
    if (!err)
	ndata->state = MDNSN_OPEN;
    else
	ndata->state = MDNSN_CLOSED;
    mdnsn_unlock(ndata);

    if (ndata->open_done)
	ndata->open_done(ndata->io, err, ndata->open_data);

    mdnsn_lock(ndata);
}

static void
child_open_cb(struct gensio *io, int err, void *cb_data)
{
    struct mdnsn_data *ndata = cb_data;

    mdnsn_lock(ndata);
    i_child_open_cb(ndata, err);
    mdnsn_deref_and_unlock(ndata);
}

static void
child_closed_cb(struct gensio *io, void *cb_data)
{
    struct mdnsn_data *ndata = cb_data;

    mdnsn_lock(ndata);
    gensio_free(ndata->child);
    ndata->child = NULL;
    mdnsn_check_close(ndata);
    mdnsn_deref_and_unlock(ndata);
}

static void
mdns_freed(struct gensio_mdns *m, void *userdata)
{
    struct mdnsn_data *ndata = userdata;

    mdnsn_lock(ndata);
    ndata->mdns_in_free = false;
    if (ndata->state == MDNSN_IN_OPEN_ERR) {
	i_child_open_cb(ndata, ndata->open_err);
    } else {
	mdnsn_check_close(ndata);
    }
    mdnsn_deref_and_unlock(ndata);
}

/* Validate that the gensio stack contains only safe gensios. */
static bool
gensiostack_ok(const char *s)
{
    unsigned int i;
    static char *ok_gensios[] = { "telnet", "tcp", "udp", "sctp", NULL };

    while (*s) {
	unsigned int len;

	for (i = 0; ok_gensios[i]; i++) {
	    len = strlen(ok_gensios[i]);
	    if (strncmp(s, ok_gensios[i], len) == 0)
		break;
	}
	if (!ok_gensios[i])
	    return false;
	s += len;
	if (*s != ',' && *s != '(' && *s != '\0')
	    return false;
	while (*s && *s != ',')
	    s++;
	if (*s == ',')
	    s++;
    }
    return true;
}

static int
addarg(char **args, gensiods *len, struct gensio_os_funcs *o,
       const char *fmt, ...)
{
    char *s, *s2;
    va_list ap;
    int err = 0;

    va_start(ap, fmt);
    if (*args) {
	int extra;

	s2 = *args;
	extra = vsnprintf(s2 + *len, 0, fmt, ap);
	/* No -1, we are deleting the ')' from the incoming string. */
	s = o->zalloc(o, *len + extra);
	if (!s) {
	    err = GE_NOMEM;
	    goto out_err;
	}
	va_end(ap);
	memcpy(s, s2, *len - 1);
	free(s2);
	va_start(ap, fmt);
	vsnprintf(s + *len - 1, extra + 1, fmt, ap);
	*args = s;
	*len += extra - 1;
    } else {
	s = gensio_alloc_vsprintf(o, fmt, ap);
	if (!s) {
	    err = GE_NOMEM;
	} else {
	    *s = '(';
	    *args = s;
	    *len = strlen(s);
	}
    }
 out_err:
    va_end(ap);

    return err;
}

static int
get_mdns_gensiostack(struct mdnsn_data *ndata, const char * const *txt,
		     const struct gensio_addr *addr, char **rstack)
{
    struct gensio_os_funcs *o = ndata->o;
    unsigned int i;
    const char *stackstr = "gensiostack=";
    unsigned int stackstrlen = strlen(stackstr);
    const char *stack, *s;
    char *addrstr = NULL;
    gensiods addrstrlen, totallen, argslen = 0, pos;
    unsigned int err;
    bool udp = false;
    char *args = NULL;

    for (i = 0; txt[i]; i++) {
	if (strncmp(txt[i], stackstr, stackstrlen) == 0)
	    break;
    }
    if (!txt[i] || !gensiostack_ok(txt[i] + stackstrlen)) {
	*rstack = NULL;
	return 0;
    }

    stack = txt[i] + stackstrlen;

    s = strrchr(stack, ',');
    if (!s)
	s = stack;
    udp = strcmp(s, "udp") == 0;

    if (ndata->readbuf_set) {
	err = addarg(&args, &argslen, o, ",readbuf=%lu)",
		     (unsigned long) ndata->max_read_size);
	if (err)
	    goto out_err;
    }

    if (ndata->nodelay_set && !udp) {
	err = addarg(&args, &argslen, o, ",nodelay=%d)", ndata->nodelay);
	if (err)
	    goto out_err;
    }

    if (ndata->laddr) {
	err = addarg(&args, &argslen, o, ",laddr=%s)", ndata->laddr);
	if (err)
	    goto out_err;
    }

    addrstrlen = 0;
    err = gensio_addr_to_str(addr, NULL, &addrstrlen, 0);
    if (err)
	goto out_err;

    totallen = strlen(stack) + addrstrlen + argslen + 2;
    addrstr = o->zalloc(o, totallen);
    if (!addrstr) {
	err = GE_NOMEM;
	goto out_err;
    }

    pos = snprintf(addrstr, totallen, "%s%s,", stack, args ? args : "");
    err = gensio_addr_to_str(addr, addrstr, &pos, totallen);
    if (err)
	goto out_err;

    *rstack = addrstr;
 out:
    if (args)
	o->free(o, args);
    return err;

 out_err:
    if (addrstr)
	o->free(o, addrstr);
    goto out;
}

static void
mdns_cb(struct gensio_mdns_watch *w,
	enum gensio_mdns_data_state state,
	int interface, int ipdomain,
	const char *name, const char *type,
	const char *domain, const char *host,
	const struct gensio_addr *addr, const char * const *txt,
	void *userdata)
{
    struct mdnsn_data *ndata = userdata;
    const char **argv = NULL;
    char *s, *stack = NULL;
    int err;

    mdnsn_lock(ndata);
    if (ndata->state != MDNSN_IN_OPEN_QUERY)
	goto out_unlock;

    if (state == GENSIO_MDNS_ALL_FOR_NOW) {
	/* Didn't find what we were looking for. */
	ndata->open_err = GE_NOTFOUND;
	goto out_err;
    }

    if (state == GENSIO_MDNS_NEW_DATA) {
	gensiods args = 0, argc = 0;

	if (!ndata->nostack) {
	    ndata->open_err = get_mdns_gensiostack(ndata, txt, addr, &stack);
	    if (ndata->open_err)
		goto out_err;
	}

	if (stack) {
	    ndata->open_err = str_to_gensio(stack, ndata->o,
					    child_cb, ndata, &ndata->child);
	    ndata->o->free(ndata->o, stack);
	} else  {
	    /* Look for the trailing protocol type. */
	    s = strrchr(type, '.');
	    if (!s)
		goto out_unlock;
	    s++;

	    if (ndata->readbuf_set) {
		ndata->open_err = gensio_argv_sappend(ndata->o, &argv, &args,
					&argc, "readbuf=%lu",
					(unsigned long) ndata->max_read_size);
		if (ndata->open_err)
		    goto out_err;
	    }

	    if (ndata->nodelay_set && strcmp(s, "_udp") != 0) {
		/* Don't add nodelay for udp. */
		ndata->open_err = gensio_argv_sappend(ndata->o, &argv, &args,
						      &argc, "nodelay=%d",
						      ndata->nodelay);
		if (ndata->open_err)
		    goto out_err;
	    }

	    if (ndata->laddr) {
		ndata->open_err = gensio_argv_sappend(ndata->o, &argv, &args,
						      &argc, "laddr=%s",
						      ndata->laddr);
		if (ndata->open_err)
		    goto out_err;
	    }

	    ndata->open_err = gensio_argv_append(ndata->o, &argv, NULL,
						 &args, &argc, false);
	    if (ndata->open_err)
		goto out_err;

	    if (strcmp(s, "_tcp") == 0) {
		ndata->open_err = gensio_terminal_alloc("tcp",
						addr, argv, ndata->o,
						child_cb, ndata,
						&ndata->child);
	    } else if (strcmp(s, "_udp") == 0) {
		ndata->open_err = gensio_terminal_alloc("udp",
						addr, argv, ndata->o,
						child_cb, ndata,
						&ndata->child);
	    } else {
		goto out_unlock;
	    }
	}
	if (ndata->open_err)
	    goto out_err;

	ndata->open_err = gensio_open(ndata->child, child_open_cb, ndata);
	if (ndata->open_err) {
	    gensio_free(ndata->child);
	    ndata->child = NULL;
	    goto out_err;
	}

	ndata->state = MDNSN_IN_CHILD_OPEN;
	if (ndata->watch)
	    gensio_mdns_remove_watch(ndata->watch, NULL, NULL);
	err = gensio_free_mdns(ndata->mdns, mdns_freed, ndata);
	if (!err) {
	    mdnsn_ref(ndata);
	    ndata->mdns_in_free = true;
	} else {
	    ndata->mdns = NULL;
	}
    }

 out_unlock:
    mdnsn_unlock(ndata);
 out:
    if (argv)
	gensio_argv_free(ndata->o, argv);
    return;

 out_err:
    ndata->state = MDNSN_IN_OPEN_ERR;
    if (ndata->watch)
	gensio_mdns_remove_watch(ndata->watch, NULL, NULL);
    err = gensio_free_mdns(ndata->mdns, mdns_freed, ndata);
    if (!err) {
	ndata->mdns_in_free = true;
    } else {
	ndata->mdns = NULL;
	i_child_open_cb(ndata, ndata->open_err);
	mdnsn_deref_and_unlock(ndata);
	goto out;
    }
    goto out_unlock;
}

static int
mdnsn_open(struct gensio *io, gensio_done_err open_done, void *open_data)
{
    struct mdnsn_data *ndata = gensio_get_gensio_data(io);
    int err = 0;

    mdnsn_lock(ndata);
    if (ndata->state != MDNSN_CLOSED) {
	err = GE_NOTREADY;
	goto out_unlock;
    }
    err = gensio_alloc_mdns(ndata->o, &ndata->mdns);
    if (err)
	goto out_unlock;
    err = gensio_mdns_add_watch(ndata->mdns, ndata->interface,
				ndata->nettype,
				ndata->name, ndata->type, ndata->domain,
				ndata->host,
				mdns_cb, ndata, &ndata->watch);
    if (err) {
	gensio_free_mdns(ndata->mdns, NULL, NULL);
	ndata->mdns = NULL;
	goto out_unlock;
    }

    mdnsn_ref(ndata);
    ndata->state = MDNSN_IN_OPEN_QUERY;
    ndata->open_done = open_done;
    ndata->open_data = open_data;
    mdnsn_start_deferred_op(ndata);
 out_unlock:
    mdnsn_unlock(ndata);

    return err;
}

static int
mdnsn_start_close(struct mdnsn_data *ndata)
{
    int err;

    switch (ndata->state) {
    case MDNSN_OPEN:
    case MDNSN_IN_CHILD_OPEN:
	err = gensio_close(ndata->child, child_closed_cb, ndata);
	if (!err) {
	    mdnsn_ref(ndata);
	} else {
	    gensio_free(ndata->child);
	    ndata->child = NULL;
	}
	break;

    case MDNSN_IN_OPEN_QUERY:
	if (ndata->watch)
	    gensio_mdns_remove_watch(ndata->watch, NULL, NULL);
	err = gensio_free_mdns(ndata->mdns, mdns_freed, ndata);
	if (err)
	    ndata->mdns = NULL;
	else {
	    ndata->mdns_in_free = true;
	    mdnsn_ref(ndata);
	}
	break;

    default:
	err = GE_NOTREADY;
    }

    return err;
}

static int
mdnsn_close(struct gensio *io, gensio_done close_done, void *close_data)
{
    struct mdnsn_data *ndata = gensio_get_gensio_data(io);
    int err = 0;

    mdnsn_lock(ndata);
    err = mdnsn_start_close(ndata);
    if (!err) {
	ndata->state = MDNSN_IN_CLOSE;
	ndata->close_done = close_done;
	ndata->close_data = close_data;
    }
    mdnsn_unlock(ndata);

    return err;
}

static void
mdnsn_free(struct gensio *io)
{
    struct mdnsn_data *ndata = gensio_get_gensio_data(io);

    mdnsn_lock(ndata);
    if (ndata->state != MDNSN_CLOSED)
	mdnsn_start_close(ndata);
    mdnsn_deref_and_unlock(ndata);
}

static int
mdnsn_disable(struct gensio *io)
{
    struct mdnsn_data *ndata = gensio_get_gensio_data(io);

    mdnsn_lock(ndata);
    gensio_disable(ndata->child);
    ndata->state = MDNSN_CLOSED;
    mdnsn_unlock(ndata);

    return 0;
}

static int
gensio_mdns_func(struct gensio *io, int func, gensiods *count,
		  const void *cbuf, gensiods buflen, void *buf,
		  const char *const *auxdata)
{
    struct mdnsn_data *ndata = gensio_get_gensio_data(io);

    switch (func) {
    case GENSIO_FUNC_WRITE_SG:
	if (!ndata->child)
	    return GE_NOTSUP;
	return gensio_write_sg(ndata->child, count, cbuf, buflen, auxdata);

    case GENSIO_FUNC_OPEN:
	return mdnsn_open(io, cbuf, buf);

    case GENSIO_FUNC_CLOSE:
	return mdnsn_close(io, cbuf, buf);

    case GENSIO_FUNC_FREE:
	mdnsn_free(io);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	if (ndata->child)
	    gensio_set_read_callback_enable(ndata->child, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	if (ndata->child)
	    gensio_set_write_callback_enable(ndata->child, buflen);
	return 0;

    case GENSIO_FUNC_DISABLE:
	return mdnsn_disable(io);

    case GENSIO_FUNC_CONTROL:
	if (!ndata->child)
	    return GE_NOTSUP;
	return gensio_control(ndata->child, 0, *((bool *) cbuf), buflen, buf,
			      count);

    default:
	return GE_NOTSUP;
    }
}

static int
mdns_ndata_setup(struct gensio_os_funcs *o, gensiods max_read_size,
		 bool nodelay, int interface, int nettype, bool nostack,
		 struct mdnsn_data **new_ndata)
{
    struct mdnsn_data *ndata;

    ndata = o->zalloc(o, sizeof(*ndata));
    if (!ndata)
	return GE_NOMEM;

    ndata->o = o;
    ndata->refcount = 1;
    ndata->max_read_size = max_read_size;
    ndata->nodelay = nodelay;
    ndata->interface = interface;
    ndata->nettype = nettype;
    ndata->nostack = nostack;

    ndata->deferred_op_runner = o->alloc_runner(o, mdnsn_deferred_op, ndata);
    if (!ndata->deferred_op_runner)
	goto out_nomem;

    ndata->lock = o->alloc_lock(o);
    if (!ndata->lock)
	goto out_nomem;

    *new_ndata = ndata;

    return 0;

 out_nomem:
    mdnsn_finish_free(ndata);

    return GE_NOMEM;
}

static int
mdns_gensio_alloc(const void *gdata, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    const char *mstr = gdata;
    int err;
    struct mdnsn_data *ndata = NULL;
    int i, interface = -1, nettype = GENSIO_NETTYPE_UNSPEC;
    bool nostack = false;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    char *laddr = NULL, *name = NULL, *type = NULL;
    char *domain = NULL, *host = NULL, *nettype_str = NULL;
    bool nodelay = false, readbuf_set = false, nodelay_set = false;
    const char *str;

    err = gensio_get_default(o, type, "nostack", false,
			     GENSIO_DEFAULT_BOOL, NULL, &i);
    if (err)
	goto out_base_free;
    nostack = i;

    err = gensio_get_default(o, type, "interface", false,
			     GENSIO_DEFAULT_INT, NULL, &interface);
    if (err)
	goto out_base_free;

    err = gensio_get_default(o, type, "nettype", false,
			     GENSIO_DEFAULT_STR, &nettype_str, NULL);
    if (err)
	goto out_base_free;

    err = gensio_get_default(o, "mdns", "name", false,
			    GENSIO_DEFAULT_STR, &name, NULL);
    if (err)
	goto out_base_free;

    err = gensio_get_default(o, "mdns", "type", false,
			    GENSIO_DEFAULT_STR, &type, NULL);
    if (err)
	goto out_base_free;

    err = gensio_get_default(o, "mdns", "domain", false,
			    GENSIO_DEFAULT_STR, &name, NULL);
    if (err)
	goto out_base_free;

    err = gensio_get_default(o, "mdns", "host", false,
			    GENSIO_DEFAULT_STR, &type, NULL);
    if (err)
	goto out_base_free;

    err = gensio_get_default(o, type, "laddr", false,
			     GENSIO_DEFAULT_STR, &laddr, NULL);
    if (err)
	goto out_base_free;

    if (mstr) {
	if (name)
	    free(name);
	name = gensio_strdup(o, mstr);
	if (!name) {
	    err = GE_NOMEM;
	    goto out_base_free;
	}
    }

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0) {
	    readbuf_set = true;
	    continue;
	}
	if (gensio_check_keybool(args[i], "nodelay", &nodelay) > 0) {
	    nodelay_set = true;
	    continue;
	}
	if (gensio_check_keybool(args[i], "nostack", &nostack) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "laddr", &str) > 0) {
	    if (laddr)
		free(laddr);
	    laddr = gensio_strdup(o, str);
	    if (!laddr) {
		err = GE_NOMEM;
		goto out_base_free;
	    }
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "name", &str) > 0) {
	    if (name)
		free(name);
	    name = gensio_strdup(o, str);
	    if (!name) {
		err = GE_NOMEM;
		goto out_base_free;
	    }
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "type", &str) > 0) {
	    if (type)
		free(type);
	    type = gensio_strdup(o, str);
	    if (!type) {
		err = GE_NOMEM;
		goto out_base_free;
	    }
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "domain", &str) > 0) {
	    if (domain)
		free(domain);
	    domain = gensio_strdup(o, str);
	    if (!domain) {
		err = GE_NOMEM;
		goto out_base_free;
	    }
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "host", &str) > 0) {
	    if (host)
		free(host);
	    host = gensio_strdup(o, str);
	    if (!host) {
		err = GE_NOMEM;
		goto out_base_free;
	    }
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "nettype", &str) > 0) {
	    if (nettype_str)
		free(nettype_str);
	    nettype_str = gensio_strdup(o, str);
	    if (!nettype_str) {
		err = GE_NOMEM;
		goto out_base_free;
	    }
	    continue;
	}
	err = GE_INVAL;
	goto out_base_free;
    }

    if (!nettype_str) {
	nettype = GENSIO_NETTYPE_UNSPEC;
    } else if (strcmp(nettype_str, "ipv4") == 0) {
	nettype = GENSIO_NETTYPE_IPV4;
    } else if (strcmp(nettype_str, "ipv6") == 0) {
	nettype = GENSIO_NETTYPE_IPV6;
    } else if (strcmp(nettype_str, "unspec") == 0) {
	nettype = GENSIO_NETTYPE_UNSPEC;
    } else {
	err = GE_INVAL;
	goto out_base_free;
    }
    o->free(o, nettype_str);
    nettype_str = NULL;

    err = mdns_ndata_setup(o, max_read_size, nodelay, interface, nettype,
			   nostack, &ndata);
    if (err)
	goto out_base_free;

    ndata->readbuf_set = readbuf_set;
    ndata->nodelay_set = nodelay_set;
    ndata->laddr = laddr;
    ndata->name = name;
    ndata->type = type;
    ndata->domain = domain;
    ndata->host = host;

    ndata->io = gensio_data_alloc(ndata->o, cb, user_data,
				  gensio_mdns_func, NULL, "mdns", ndata);
    if (!ndata->io)
	goto out_nomem;
    gensio_set_is_client(ndata->io, true);
    gensio_set_is_reliable(ndata->io, true);

    *new_gensio = ndata->io;

    return 0;

 out_nomem:
    mdnsn_finish_free(ndata);
    return GE_NOMEM;
 out_base_free:
    if (laddr)
	o->free(o, laddr);
    if (name)
	o->free(o, name);
    if (type)
	o->free(o, type);
    if (domain)
	o->free(o, domain);
    if (host)
	o->free(o, host);
    if (nettype_str)
	o->free(o, nettype_str);
    return err;
}

static int
str_to_mdns_gensio(const char *str, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    return mdns_gensio_alloc(str, args, o, cb, user_data, new_gensio);
}

int
gensio_init_mdns(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio(o, "mdns", str_to_mdns_gensio, mdns_gensio_alloc);
    if (rv)
	return rv;
    return 0;
}
