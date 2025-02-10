/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <gensio/gensio_mdns.h>

#if HAVE_MDNS
#include <string.h>
#include <assert.h>
#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#ifdef __MSYS__
typedef struct in6_addr IN6_ADDR;
#include <iphlpapi.h>
#endif
#endif
#include <gensio/gensio.h>
#include <gensio/gensio_list.h>
#include <gensio/argvutils.h>

#if HAVE_AVAHI
#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-client/lookup.h>
#include <avahi-common/error.h>
#include "avahi_watcher.h"

#elif HAVE_DNSSD
#include <dns_sd.h>

#elif HAVE_WINMDNS
#include <windows.h>
#include <windns.h>
#endif

/* Returns true on failure (error) */
static bool
dupstr(struct gensio_os_funcs *o, const char *src, char **dest)
{
    if (src) {
	char *ret = gensio_strdup(o, src);
	if (!ret)
	    return true;
	*dest = ret;
    }
    return false;
}

struct gensio_mdns_service;

struct gensio_mdns {
    struct gensio_os_funcs *o;

    struct gensio_list services;
    struct gensio_list watches;

#if HAVE_AVAHI
    AvahiPoll *ap;
    AvahiClient *ac;
    AvahiClientState state;

#elif HAVE_DNSSD
    DNSServiceRef dnssd_sref;
    struct gensio_iod *iod;
    int dnssd_fd;
#endif

#if HAVE_DNSSD || HAVE_WINMDNS
    struct gensio_lock *lock;
#endif

    unsigned int refcount;

    bool freed;
    gensio_mdns_done free_done;
    void *free_userdata;

    bool runner_pending;
    struct gensio_runner *runner;
    struct gensio_list callbacks;
};

static void
gensio_mdns_vlog(struct gensio_mdns *m, enum gensio_log_levels l,
		 char *fmt, va_list ap)
{
    gensio_vlog(m->o, l, fmt, ap);
}

static void
gensio_mdns_log(struct gensio_mdns *m, enum gensio_log_levels l, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    gensio_mdns_vlog(m, l, fmt, ap);
    va_end(ap);
}

struct mdns_str_data {
    void (*cleanup)(struct gensio_os_funcs *, struct mdns_str_data *);
    bool (*cmp)(struct mdns_str_data *, const char *str);
    void *extdata;
};

/* Returns true if compare string is NULL or if the strings compare. */
static bool
mdns_rawstr_cmp(struct mdns_str_data *sdata, const char *str)
{
    if (!sdata->extdata)
	return true;

    return strcmp(str, sdata->extdata) == 0;
}

static void
mdns_rawstr_cleanup(struct gensio_os_funcs *o, struct mdns_str_data *sdata)
{
    if (sdata->extdata)
	o->free(o, sdata->extdata);
}

#if defined(HAVE_REGEXEC) || defined(HAVE_PCRE_POSIX)
#include <sys/types.h>
#ifdef HAVE_PCRE_POSIX
#include <pcreposix.h>
#else
#include <regex.h>
#endif

static void
regex_str_cleanup(struct gensio_os_funcs *o, struct mdns_str_data *sdata)
{
    regfree(sdata->extdata);
    o->free(o, sdata->extdata);
}

static bool
regex_str_cmp(struct mdns_str_data *sdata, const char *str)
{
    return regexec(sdata->extdata, str, 0, NULL, 0) == 0;
}

static int
regex_str_setup(struct gensio_mdns *m, const char *str1,
		struct mdns_str_data *sdata)
{
    struct gensio_os_funcs *o = m->o;
    int rv;

    sdata->extdata = o->zalloc(o, sizeof(regex_t));
    if (!sdata->extdata)
	return GE_NOMEM;

    rv = regcomp(sdata->extdata, str1 + 1, REG_NOSUB);
    if (rv) {
	char errbuf[200];

	regerror(rv, sdata->extdata, errbuf, sizeof(errbuf));
	gensio_mdns_log(m, GENSIO_LOG_ERR, "mdns: regex error: %s",
			errbuf);
	regfree(sdata->extdata);
	o->free(o, sdata->extdata);
	sdata->extdata = NULL;
	if (rv == REG_ESPACE)
	    return GE_NOMEM;
	return GE_INVAL;
    }

    sdata->cmp = regex_str_cmp;
    sdata->cleanup = regex_str_cleanup;
    return 0;
}
#else
static int
regex_str_setup(struct gensio_mdns *m, const char *str1,
		struct mdns_str_data *sdata)
{
    gensio_mdns_log(m, GENSIO_LOG_ERR, "mdns: regex not supported");
    return GE_NOTSUP;
}
#endif

#ifdef HAVE_FNMATCH
#include <fnmatch.h>

static void
glob_str_cleanup(struct gensio_os_funcs *o, struct mdns_str_data *sdata)
{
    o->free(o, sdata->extdata);
}

static bool
glob_str_cmp(struct mdns_str_data *sdata, const char *str)
{
    return fnmatch(sdata->extdata, str, 0) == 0;
}

static int
glob_str_setup(struct gensio_mdns *m, const char *str1,
		struct mdns_str_data *sdata)
{
    struct gensio_os_funcs *o = m->o;

    sdata->extdata = gensio_strdup(o, str1 + 1);
    if (!sdata->extdata)
	return GE_NOMEM;
    sdata->cmp = glob_str_cmp;
    sdata->cleanup = glob_str_cleanup;

    return 0;
}
#else
static int
glob_str_setup(struct gensio_mdns *m, const char *str1,
		struct mdns_str_data *sdata)
{
    gensio_mdns_log(m, GENSIO_LOG_ERR, "mdns: glob not supported");
    return GE_NOTSUP;
}
#endif

static int
mdns_str_setup(struct gensio_mdns *m, const char *str1,
	       struct mdns_str_data *sdata)
{
    struct gensio_os_funcs *o = m->o;

    if (str1 && str1[0] == '%')
	return regex_str_setup(m, str1, sdata);

    if (str1 && str1[0] == '@')
	return glob_str_setup(m, str1, sdata);

    if (str1 && str1[0] == '=')
	str1++;

    if (str1) {
	sdata->extdata = gensio_strdup(o, str1);
	if (!sdata->extdata)
	    return GE_NOMEM;
    } else {
	sdata->extdata = NULL;
    }
    sdata->cmp = mdns_rawstr_cmp;
    sdata->cleanup = mdns_rawstr_cleanup;
    return 0;
}

static bool
mdns_str_cmp(struct mdns_str_data *sdata, const char *str)
{
    return sdata->cmp(sdata, str);
}

static void
mdns_str_cleanup(struct gensio_os_funcs *o, struct mdns_str_data *sdata)
{
    if (sdata->cleanup)
	sdata->cleanup(o, sdata);
}

static void
gensio_mdns_finish_free(struct gensio_mdns *m)
{
    struct gensio_os_funcs *o = m->o;

    if (m->free_done)
	m->free_done(m, m->free_userdata);
    if (m->runner)
	o->free_runner(m->runner);
    o->free(o, m);
}

#if HAVE_AVAHI

static int
protocol_to_avahi_protocol(int protocol, AvahiProtocol *aprotocol)
{
    switch(protocol) {
    case GENSIO_NETTYPE_IPV4: *aprotocol = AVAHI_PROTO_INET; break;
    case GENSIO_NETTYPE_IPV6: *aprotocol = AVAHI_PROTO_INET6; break;
    case GENSIO_NETTYPE_UNSPEC: *aprotocol = AVAHI_PROTO_UNSPEC; break;
    default:
	return GE_INVAL;
    }
    return 0;
}

static int
avahi_protocol_to_protocol(AvahiProtocol aprotocol, int *protocol)
{
    switch(aprotocol) {
    case AVAHI_PROTO_UNSPEC:
	*protocol = GENSIO_NETTYPE_UNSPEC;
	return 0;

    case AVAHI_PROTO_INET:
	*protocol = GENSIO_NETTYPE_IPV4;
	return 0;

#ifdef AF_INET6
    case AVAHI_PROTO_INET6:
	*protocol = GENSIO_NETTYPE_IPV6;
	return 0;
#endif

    default:
	return GE_INVAL;
    }
}

static AvahiIfIndex
interface_to_avahi_interface(int ifinterface)
{
    if (ifinterface == -1)
	return AVAHI_IF_UNSPEC;
    return ifinterface;
}

static int avahi_interface_to_interface(AvahiIfIndex ainterface)
{
    return ainterface;
}

static void
gensio_mdns_lock(struct gensio_mdns *m)
{
    gensio_avahi_lock(m->ap);
}

static void
gensio_mdns_unlock(struct gensio_mdns *m)
{
    gensio_avahi_unlock(m->ap);
}

static void
avahi_finish_free(AvahiPoll *ap, void *userdata)
{
    struct gensio_mdns *m = userdata;

    /* Make sure everything is out of the lock. */
    gensio_mdns_lock(m);
    gensio_mdns_unlock(m);

    gensio_mdns_finish_free(m);
}

static int
gensio_mdnslib_init(struct gensio_mdns *m)
{
    m->ap = alloc_gensio_avahi_poll(m->o);
    if (!m->ap)
	return GE_NOMEM;
    return 0;
}

static void
gensio_mdnslib_free(struct gensio_mdns *m)
{
    if (m->ac) {
	/* We are fully initialized */
	avahi_client_free(m->ac);
	gensio_avahi_poll_free(m->ap, avahi_finish_free, m);
    } else {
	gensio_avahi_poll_free(m->ap, NULL, NULL);
	gensio_mdns_finish_free(m);
    }
}

#elif HAVE_DNSSD

static int
i_dnssd_err_to_err(struct gensio_mdns *m, DNSServiceErrorType derr,
		   int lineno)
{
    int err;

    switch (derr) {
    case kDNSServiceErr_Unknown:		err = GE_OSERR; break;
    case kDNSServiceErr_NoSuchName:		err = GE_NOTFOUND; break;
    case kDNSServiceErr_NoMemory:		err = GE_NOMEM; break;
    case kDNSServiceErr_BadParam:		err = GE_INVAL; break;
    case kDNSServiceErr_BadReference:		err = GE_OSERR; break;
    case kDNSServiceErr_BadState:		err = GE_INCONSISTENT; break;
    case kDNSServiceErr_BadFlags:		err = GE_INVAL; break;
    case kDNSServiceErr_Unsupported:		err = GE_NOTSUP; break;
    case kDNSServiceErr_NotInitialized:		err = GE_NOTREADY; break;
    case kDNSServiceErr_AlreadyRegistered:	err = GE_INUSE; break;
    case kDNSServiceErr_NameConflict:		err = GE_EXISTS; break;
    case kDNSServiceErr_Invalid:		err = GE_INVAL; break;
    case kDNSServiceErr_Firewall:		err = GE_OSERR; break;
    case kDNSServiceErr_Incompatible:		err = GE_INCONSISTENT; break;
    case kDNSServiceErr_BadInterfaceIndex:	err = GE_INVAL; break;
    case kDNSServiceErr_Refused:		err = GE_CONNREFUSE; break;
    case kDNSServiceErr_NoSuchRecord:		err = GE_NOTFOUND; break;
    case kDNSServiceErr_NoAuth:			err = GE_AUTHREJECT; break;
    case kDNSServiceErr_NoSuchKey:		err = GE_KEYINVALID; break;
    case kDNSServiceErr_NATTraversal:		err = GE_OSERR; break;
    case kDNSServiceErr_DoubleNAT:		err = GE_OSERR; break;
    case kDNSServiceErr_BadTime:		err = GE_INVAL; break;
    case kDNSServiceErr_BadSig:			err = GE_CERTINVALID; break;
    case kDNSServiceErr_BadKey:			err = GE_KEYINVALID; break;
    case kDNSServiceErr_Transient:		err = GE_OSERR; break;
    case kDNSServiceErr_ServiceNotRunning:	err = GE_NOTREADY; break;
    case kDNSServiceErr_NATPortMappingUnsupported: err = GE_OSERR; break;
    case kDNSServiceErr_NATPortMappingDisabled:	err = GE_OSERR; break;
    case kDNSServiceErr_NoRouter:		err = GE_OSERR; break;
    case kDNSServiceErr_PollingMode:		err = GE_OSERR; break;
    case kDNSServiceErr_Timeout:		err = GE_TIMEDOUT; break;
    case kDNSServiceErr_DefunctConnection:	err = GE_OSERR; break;
    case kDNSServiceErr_PolicyDenied:		err = GE_OSERR; break;
#ifdef kDNSServiceErr_NotPermitted
    case kDNSServiceErr_NotPermitted:		err = GE_PERM; break;
#endif
    default: err = GE_OSERR;
    }
    /* FIXME - DNSSD doesn't provide a string translation. */
    if (err == GE_OSERR) {
	gensio_mdns_log(m, GENSIO_LOG_ERR, "DNSSD error on line %d: %d",
			lineno, derr);
    }
    return err;
}
#define dnssd_err_to_err(m, err) i_dnssd_err_to_err(m, err, __LINE__)

static int
interface_to_dnssd_interface(int ifinterface, uint32_t *sinterface)
{
    /*
     * FIXME - is this right? interface 0 is always localhost, so you
     * don't run mdns on that, so that's why zero is use as all
     * interfaces?
     */
    if (ifinterface == 0)
	return GE_INVAL;
    if (ifinterface < 0) {
	*sinterface = 0;
	return 0;
    }
    *sinterface = ifinterface;
    return 0;
}

static int
dnssd_interface_to_interface(uint32_t sinterface)
{
    return sinterface;
}

static int
protocol_to_dnssd_protocol(int protocol, DNSServiceProtocol *sprotocol)
{
    switch (protocol) {
    case GENSIO_NETTYPE_UNSPEC:
	*sprotocol = kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6;
	break;
    case GENSIO_NETTYPE_IPV4: *sprotocol = kDNSServiceProtocol_IPv4; break;
    case GENSIO_NETTYPE_IPV6: *sprotocol = kDNSServiceProtocol_IPv6; break;
    default: return GE_INVAL;
    }
    return 0;
}

/*
 * dnssd strings end in a '.', but the gensio ones don't.  Compensate.
 */
static char *
dnssd_str_fix(struct gensio_os_funcs *o, const char *str)
{
    gensiods len;

    if (!str)
	return NULL;
    len = strlen(str);
    if (len < 2)
	return NULL;
    return gensio_strndup(o, str, len - 1);
}

#endif

#if HAVE_DNSSD || HAVE_WINMDNS

static int
gensio_mdnslib_init(struct gensio_mdns *m)
{
    m->lock = m->o->alloc_lock(m->o);
    if (!m->lock)
	return GE_NOMEM;
    return 0;
}

static void
gensio_mdnslib_free(struct gensio_mdns *m)
{
    m->o->free_lock(m->lock);
    gensio_mdns_finish_free(m);
}

static void
gensio_mdns_lock(struct gensio_mdns *m)
{
    m->o->lock(m->lock);
}

static void
gensio_mdns_unlock(struct gensio_mdns *m)
{
    m->o->unlock(m->lock);
}
#endif

static void
gensio_mdns_ref(struct gensio_mdns *m)
{
    m->refcount++;
}

static void
gensio_mdns_deref(struct gensio_mdns *m)
{
    /* Can't use this for the final deref. */
    assert(m->refcount > 1);
    m->refcount--;
}

static void
gensio_mdns_deref_and_unlock(struct gensio_mdns *m)
{
    assert(m->refcount > 0);
    m->refcount--;
    if (m->refcount == 0) {
	gensio_mdns_unlock(m);
	gensio_mdnslib_free(m);
	return;
    }
    gensio_mdns_unlock(m);
}

struct gensio_mdns_callback {
    struct gensio_link link;

    bool in_queue;

    bool remove; /* Remove the watch/service. */

    bool namechange; /* Service name changed. */

    /*
     * Report that no more watch data is pending or that a service has
     * finished.
     */
    bool all_for_now;

    struct gensio_mdns_watch *w;
    struct gensio_mdns_service *s;

    struct gensio_mdns_watch_data *data;
};

static void
enqueue_callback(struct gensio_mdns *m, struct gensio_mdns_callback *c)
{
    if (c->remove)
	return;
    if (!c->in_queue) {
	gensio_list_add_tail(&m->callbacks, &c->link);
	c->in_queue = true;
	gensio_mdns_ref(m);
    }
    if (!m->runner_pending) {
	m->runner_pending = true;
	gensio_mdns_ref(m);
	m->o->run(m->runner);
    }
}

/*
 * Service Advertising
 *
 * Code following deals with advertising services on the network.
 * It's pretty simple, in all libraries you just call a function with
 * the right parameters and it advertises.  It gives you a handle to
 * cancel the operation.
 */
#if HAVE_WINMDNS
struct gensio_mdns_req_info {
    bool is_dereg;
    struct gensio_mdns_service *s;
};
#endif

struct gensio_mdns_service {
    struct gensio_link link;
    struct gensio_mdns *m;

    char *name;
    char *type;
    char *domain;
    char *host;
    int port;

    bool removed;

    gensio_mdns_service_cb cb;
    void *cb_data;

    struct gensio_mdns_callback cbdata;

    bool reported;

#if HAVE_AVAHI
    AvahiIfIndex avahi_interface;
    AvahiProtocol avahi_protocol;
    AvahiStringList *txt;

    AvahiEntryGroup *group;

#elif HAVE_DNSSD
    uint32_t dnssd_interface;
    DNSServiceProtocol dnssd_protocol;
    char *dnssd_txt;
    uint32_t dnssd_txtlen;

    bool dnssd_started;
    DNSServiceRef dnssd_sref;

#elif HAVE_WINMDNS
    int win_interface;
    int win_protocol;
    wchar_t **win_keys;
    wchar_t **win_values;
    unsigned int win_kvcount;
    wchar_t *win_host;
    wchar_t *win_name;
    DNS_SERVICE_REGISTER_REQUEST req;
    DNS_SERVICE_REGISTER_REQUEST dereq;
    struct gensio_mdns_req_info reginfo;
    struct gensio_mdns_req_info dereginfo;
    DNS_SERVICE_INSTANCE inst;
    DNS_SERVICE_CANCEL cancel;
#endif

    /* Used to handle name collisions. */
    unsigned int nameseq;
    gensio_cntstr *currname;
};

static void gensio_mdnslib_add_service(struct gensio_mdns_service *s);

#if HAVE_AVAHI
/* Lock should already be held when calling this. */
static void
avahi_group_callback(AvahiEntryGroup *group, AvahiEntryGroupState state,
		     void *userdata)
{
    struct gensio_mdns_service *s = userdata;
    struct gensio_mdns *m = s->m;
    struct gensio_os_funcs *o = m->o;

    if (state == AVAHI_ENTRY_GROUP_COLLISION) {
	gensio_cntstr *newname;
	int err;

	s->nameseq++;
	err = gensio_cntstr_sprintf(o, &newname, "%s(%u)", s->name, s->nameseq);
	if (err) {
	    gensio_mdns_log(m, GENSIO_LOG_ERR,
			    "Out of memory in group collision: %s",
			    gensio_err_to_str(err));
	    goto done;
	}
	gensio_cntstr_free(o, s->currname);
	s->currname = newname;

	gensio_mdns_log(m, GENSIO_LOG_WARNING,
			"service %s renamed to %s", s->name,
			gensio_cntstr_get(s->currname));

	gensio_mdnslib_add_service(s);
	s->cbdata.namechange = true;
	enqueue_callback(m, &s->cbdata);
    }
    /* FIXME - handle other states. */
 done:
    if (!s->reported) {
	s->reported = true;
	enqueue_callback(m, &s->cbdata);
    }
}

/* Must be called with the Avahi poll lock held. */
static void
gensio_mdnslib_add_service(struct gensio_mdns_service *s)
{
    struct gensio_mdns *m = s->m;
    struct gensio_os_funcs *o = m->o;;
    int err;

    if (m->state != AVAHI_CLIENT_S_RUNNING)
	/* We'll catch it later. */
	return;

    if (!s->group)
	s->group = avahi_entry_group_new(m->ac, avahi_group_callback, s);
    if (!s->group) {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Out of memory adding a service");
	return;
    }
 retry:
    err = avahi_entry_group_add_service_strlst(s->group, s->avahi_interface,
					       s->avahi_protocol, 0,
					       gensio_cntstr_get(s->currname),
					       s->type, s->domain, s->host,
					       s->port, s->txt);
    if (err == AVAHI_ERR_COLLISION) {
	gensio_cntstr *newname;

	s->nameseq++;
	err = gensio_cntstr_sprintf(o, &newname, "%s(%u)", s->name, s->nameseq);
	if (err) {
	    gensio_mdns_log(m, GENSIO_LOG_ERR,
			    "Error allocating service strings: %s",
			    gensio_err_to_str(err));
	    return;
	}
	gensio_cntstr_free(o, s->currname);
	s->currname = newname;
	goto retry;
    } else if (err) {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error adding service strings: %s",
			avahi_strerror(err), err);
	return;
    }
    err = avahi_entry_group_commit(s->group);
    if (err)
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error committing service entry: %s",
			avahi_strerror(err));
}

static int
gensio_mdnslib_initservice(struct gensio_mdns_service *s,
			   int ipdomain, int ifinterface,
			   const char * const *txt)
{
    int err;

    err = protocol_to_avahi_protocol(ipdomain, &s->avahi_protocol);
    if (err)
	return err;

    if (ifinterface < 0)
	s->avahi_interface = AVAHI_IF_UNSPEC;
    else
	s->avahi_interface = ifinterface;

    if (txt && txt[0]) {
	s->txt = avahi_string_list_new_from_array((const char **) txt, -1);
	if (!s->txt)
	    return GE_NOMEM;
    }

    return 0;
}

/* Must be called with the Avahi poll lock held. */
static void
gensio_mdnslib_free_service(struct gensio_os_funcs *o,
			    struct gensio_mdns_service *s)
{
    if (s->group)
	avahi_entry_group_free(s->group);
    if (s->txt)
	avahi_string_list_free(s->txt);
}

static void
gensio_mdnslib_remove_service(struct gensio_mdns_service *s)
{
    enqueue_callback(s->m, &s->cbdata);
    s->cbdata.remove = true;
}

#elif HAVE_DNSSD

static void
dnssd_service_done(DNSServiceRef sdRef,
		   DNSServiceFlags flags,
		   DNSServiceErrorType errorCode,
		   const char *name,
		   const char *regtype,
		   const char *domain,
		   void *context)
{
    struct gensio_mdns_service *s = context;
    struct gensio_mdns *m = s->m;

    if (errorCode) {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error from service registration: %d", errorCode);
	return;
    }

    if (strcmp(name, gensio_cntstr_get(s->currname)) != 0) {
	gensio_cntstr *newname;
	int err;

	gensio_mdns_log(m, GENSIO_LOG_WARNING,
			"service %s renamed to %s", s->name, name);

	err = gensio_cntstr_make(m->o, name, &newname);
	if (err) {
	    gensio_mdns_log(m, GENSIO_LOG_ERR,
			    "Allocation error in group collision: %s",
			    gensio_err_to_str(err));
	    goto done;
	}
	gensio_cntstr_free(m->o, s->currname);
	s->currname = newname;
	s->cbdata.namechange = true;
	enqueue_callback(m, &s->cbdata);
    }
 done:
    if (!s->reported) {
	s->reported = true;
	enqueue_callback(m, &s->cbdata);
    }
}

static void
gensio_mdnslib_add_service(struct gensio_mdns_service *s)
{
    struct gensio_mdns *m = s->m;
    DNSServiceErrorType derr;

    s->dnssd_sref = m->dnssd_sref;
    derr = DNSServiceRegister(&s->dnssd_sref, kDNSServiceFlagsShareConnection,
			      s->dnssd_interface,
			      s->name, s->type, s->domain, s->host,
			      htons(s->port),
			      s->dnssd_txtlen, s->dnssd_txt,
			      dnssd_service_done, s);
    if (derr)
	gensio_mdns_log(m, GENSIO_LOG_ERR, "Error registering service: %d",
			derr);
}

static int
gensio_mdnslib_initservice(struct gensio_mdns_service *s,
			   int ipdomain, int ifinterface,
			   const char * const *txt)
{
    struct gensio_mdns *m = s->m;
    int err;

    err = interface_to_dnssd_interface(ifinterface, &s->dnssd_interface);
    if (err)
	return err;
    err = protocol_to_dnssd_protocol(ipdomain, &s->dnssd_protocol);
    if (err)
	return err;

    if (txt && txt[0]) {
	unsigned int i, len = 0, p;
	char *dtxt;

	for (i = 0; txt[i]; i++)
	    len += strlen(txt[i]) + 1;

	if (len > 65535)
	    return GE_INVAL;

	dtxt = m->o->zalloc(m->o, len);
	if (!dtxt)
	    return GE_NOMEM;

	for (len = 0, i = 0; txt[i]; i++) {
	    p = strlen(txt[i]);
	    dtxt[len++] = p;
	    memcpy(dtxt + len, txt[i], p);
	    len += p;
	}
	s->dnssd_txt = dtxt;
	s->dnssd_txtlen = len;
    }

    return 0;
}

static void
gensio_mdnslib_free_service(struct gensio_os_funcs *o,
			    struct gensio_mdns_service *s)
{
    if (s->dnssd_started)
	DNSServiceRefDeallocate(s->dnssd_sref);
    if (s->dnssd_txt)
	o->free(o, s->dnssd_txt);
}

static void
gensio_mdnslib_remove_service(struct gensio_mdns_service *s)
{
    enqueue_callback(s->m, &s->cbdata);
    s->cbdata.remove = true;
}

#elif HAVE_WINMDNS

/*
 * It is completely unclear from the Windows documentation how to use
 * DNSServiceBrowse().  It seemed at first that you had to add every
 * individual IP address.  Then I experimented with just adding one IP
 * address for an interface, and it didn't make any difference.
 * Setting both IP addresses to NULL didn't make any difference.
 *
 * No matter what, all the IP addresses for an interface are added
 * with a single registration.  I have no idea if the IfIndex field
 * works, I don't have a system with two IP interfaces.
 *
 * There is also no way to set the protocol field for registering a
 * service.  All the IP addresses are added no matter what.
 *
 * Also, if you cancel with DNSServiceBrowseCancel, you don't get
 * another callback saying the cancel is complete.  So it may be racy
 * and there may be nothing that can be done about it.  I can't tell
 * if the cancel waits until it is out of the callback, there is no
 * documentation about how any of this works.
 *
 * When the browser callback is called, it is called each time with
 * all known IP addresses.  So you have to scan that list and check
 * for removals.  Again, completely undocumented.
 *
 * So it works like Avahi and DNSSD work, sort of.
 */

static int
str_to_wchar(struct gensio_os_funcs *o, const char *s, wchar_t **rws)
{
    size_t len;
    wchar_t *ws;

    len = mbstowcs(NULL, s, 0);
    if (len == (size_t) -1)
	return GE_INVAL;

    len++;
    ws = o->zalloc(o, len * sizeof(wchar_t));
    if (!ws)
	return GE_NOMEM;

    mbstowcs(ws, s, len);
    *rws = ws;
    return 0;
}

static int
str_to_wcharn(struct gensio_os_funcs *o, const char *is, gensiods n,
	      wchar_t **rws)
{
    size_t len;
    wchar_t *ws;
    char *s = gensio_strndup(o, is, n);

    if (!s)
	return GE_NOMEM;

    len = mbstowcs(NULL, s, 0);
    if (len == (size_t) -1) {
	o->free(o, s);
	return GE_INVAL;
    }

    len++;
    ws = o->zalloc(o, len * sizeof(wchar_t));
    if (!ws) {
	o->free(o, s);
	return GE_NOMEM;
    }

    mbstowcs(ws, s, len);
    o->free(o, s);
    *rws = ws;
    return 0;
}

static int
wchar_to_str(struct gensio_os_funcs *o, const wchar_t *ws, char **rs)
{
    size_t len;
    char *s;

    len = wcstombs(NULL, ws, 0);
    if (len == (size_t) -1)
	return GE_INVAL;

    len++;
    s = o->zalloc(o, len);
    if (!s)
	return GE_NOMEM;

    wcstombs(s, ws, len);
    *rs = s;
    return 0;
}

static int
wstring_array_to_argv(struct gensio_os_funcs *o, gensiods len,
		      wchar_t **wstrs, const char ***rstrs)
{
    const char **strs = NULL;
    char *s;
    gensiods args = 0, argc = 0;
    int err = 0;
    unsigned int i;

    for (i = 0; i < len; i++) {
	err = wchar_to_str(o, wstrs[i], &s);
	if (err)
	    goto out_err;
	err = gensio_argv_append(o, &strs, s, &args, &argc, false);
	if (err) {
	    o->free(o, s);
	    goto out_err;
	}
    }
    err = gensio_argv_append(o, &strs, NULL, &args, &argc, false);
    if (err)
	goto out_err;
    *rstrs = strs;
    return 0;

 out_err:
    if (strs)
	gensio_argv_free(o, strs);
    return err;
}

static void WINAPI
win_serv_done(DWORD Status, void *context,
	      DNS_SERVICE_INSTANCE *inst)
{
    struct gensio_mdns_req_info *reginfo = context;
    struct gensio_mdns_service *s = reginfo->s;
    struct gensio_mdns *m = s->m;
    struct gensio_os_funcs *o = m->o;
    int err;

    gensio_mdns_lock(m);
    if (reginfo->is_dereg) {
	enqueue_callback(s->m, &s->cbdata);
	s->cbdata.remove = true;
	goto out_done;
    } else if (Status == ERROR_CANCELLED) {
	/* Nothing to do here, on a cancellation we will get a dereg after. */
	goto out_done;
    } else if (Status != ERROR_SUCCESS) {
	err = gensio_os_err_to_err(m->o, Status);
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error from service register callback: %s",
			gensio_err_to_str(err));
    } else if (inst) {
	char *name = NULL, *dot;

	err = wchar_to_str(o, inst->pszInstanceName, &name);
	if (err) {
	    gensio_mdns_log(m, GENSIO_LOG_ERR,
			    "Error allocating winserv string: %s",
			    gensio_err_to_str(err));
	    goto out_free;
	}

	dot = strrchr(name, '.');
	if (!dot || dot == name)
	    goto out_invalid_name;
	*dot = '\0';
	dot = strrchr(name, '.');
	if (!dot || dot == name)
	    goto out_invalid_name;
	*dot = '\0';
	dot = strrchr(name, '.');
	if (!dot || dot == name)
	    goto out_invalid_name;
	*dot = '\0';

	if (strcmp(name, gensio_cntstr_get(s->currname)) != 0) {
	    gensio_cntstr *newname;

	    err = gensio_cntstr_make(o, name, &newname);
	    if (err) {
		gensio_mdns_log(m, GENSIO_LOG_ERR,
				"Error allocating winserv cntstr: %s",
				gensio_err_to_str(err));
		goto out_free;
	    }
	    gensio_cntstr_free(o, s->currname);
	    s->currname = newname;
	    s->cbdata.namechange = true;
	    if (s->reported)
		enqueue_callback(m, &s->cbdata);
	}
	goto out_free;

    out_invalid_name:
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Invalid mdns name in winserv callback: %ls",
			inst->pszInstanceName);
    out_free:
	if (name)
	    o->free(o, name);
    }

    if (!s->reported) {
	s->reported = true;
	enqueue_callback(m, &s->cbdata);
    }

 out_done:
    if (inst)
	DnsServiceFreeInstance(inst);
    gensio_mdns_unlock(m);
}

static void
gensio_mdnslib_add_service(struct gensio_mdns_service *s)
{
    struct gensio_os_funcs *o = s->m->o;
    DWORD rv;
    int err;

    s->req.Version = DNS_QUERY_REQUEST_VERSION1;
    s->req.InterfaceIndex = s->win_interface;
    s->req.pServiceInstance = &s->inst;
    s->req.pRegisterCompletionCallback = win_serv_done;
    s->req.unicastEnabled = false;

    s->dereq = s->req;

    s->inst.pszInstanceName = s->win_name;
    s->inst.pszHostName = s->win_host;
    s->inst.wPort = s->port;
    s->inst.wPriority = 0;
    s->inst.wWeight = 0;
    s->inst.dwPropertyCount = s->win_kvcount;
    s->inst.keys = s->win_keys;
    s->inst.values = s->win_values;

    s->reginfo.is_dereg = false;
    s->reginfo.s = s;

    s->dereginfo.is_dereg = true;
    s->dereginfo.s = s;

    s->req.pQueryContext = &s->reginfo;
    s->dereq.pQueryContext = &s->dereginfo;

    rv = DnsServiceRegister(&s->req, &s->cancel);
    if (rv != DNS_REQUEST_PENDING) {
	err = gensio_os_err_to_err(o, rv);
	goto out_err;
    }

    return;

 out_err:
    gensio_mdns_log(s->m, GENSIO_LOG_ERR, "Error registering service: %s",
		    gensio_err_to_str(err));
}

static int
gensio_mdnslib_initservice(struct gensio_mdns_service *s,
			   int ipdomain, int ifinterface,
			   const char * const *txt)
{
    struct gensio_os_funcs *o = s->m->o;
    unsigned int i, kvcount = 0;
    wchar_t **keys = NULL, **values = NULL;
    char *domain = s->domain, *tmps, *chost;
    char hostname[256];
    wchar_t *name = NULL, *host = NULL;
    int err = 0;

    if (ifinterface == 0)
	return GE_INVAL;
    s->win_protocol = ipdomain;
    if (ifinterface == -1)
	s->win_interface = 0;
    else
	s->win_interface = ifinterface;

    if (!domain)
	domain = "local";

    if (s->host) {
	chost = s->host;
    } else {
	if (gethostname(hostname, sizeof(hostname)) != 0) {
	    err = GE_NOTFOUND;
	    goto out_err;
	}
	chost = hostname;
    }

    /* You have to construct full names for this to work. */
    tmps = gensio_alloc_sprintf(o, "%s.%s", chost, domain);
    if (!tmps)
	goto out_nomem;
    err = str_to_wchar(o, tmps, &host);
    o->free(o, tmps);
    if (err)
	goto out_err;

    tmps = gensio_alloc_sprintf(o, "%s.%s.%s", s->name, s->type, domain);
    if (!tmps)
	goto out_nomem;
    err = str_to_wchar(o, tmps, &name);
    o->free(o, tmps);
    if (err)
	goto out_err;

    if (txt && txt[0]) {
	for (kvcount = 0; txt[kvcount]; kvcount++)
	    ;
	keys = o->zalloc(o, kvcount * sizeof(*keys));
	if (!keys)
	    goto out_nomem;
	values = o->zalloc(o, kvcount * sizeof(*values));
	if (!values)
	    goto out_nomem;
	for (i = 0; i < kvcount; i++) {
	    char *vp = strchr(txt[i], '=');

	    if (!vp)
		goto out_inval;
	    err = str_to_wcharn(o, txt[i], vp - txt[i], &(keys[i]));
	    if (err)
		goto out_err;
	    err = str_to_wchar(o, vp + 1, &(values[i]));
	    if (err)
		goto out_err;
	}
	s->win_keys = keys;
	s->win_values = values;
	s->win_kvcount = kvcount;
    }
    s->win_name = name;
    s->win_host = host;
    return 0;
 out_nomem:
    err = GE_NOMEM;
    goto out_err;
 out_inval:
    err = GE_INVAL;
 out_err:
    if (name)
	o->free(o, name);
    if (host)
	o->free(o, host);
    if (keys) {
	for (i = 0; i < kvcount; i++) {
	    if (keys[i])
		o->free(o, keys[i]);
	}
    }
    if (values) {
	for (i = 0; i < kvcount; i++) {
	    if (values[i])
		o->free(o, values[i]);
	}
    }
    return err;
}

static void
gensio_mdnslib_free_service(struct gensio_os_funcs *o, struct gensio_mdns_service *s)
{
    wchar_t **keys = s->win_keys, **values = s->win_values;
    unsigned int i, kvcount = s->win_kvcount;

    if (keys) {
	for (i = 0; i < kvcount; i++) {
	    if (keys[i])
		o->free(o, keys[i]);
	}
	o->free(o, keys);
    }
    if (values) {
	for (i = 0; i < kvcount; i++) {
	    if (values[i])
		o->free(o, values[i]);
	}
	o->free(o, values);
    }
    if (s->win_name)
	o->free(o, s->win_name);
    if (s->win_host)
	o->free(o, s->win_host);
}

static void
gensio_mdnslib_remove_service(struct gensio_mdns_service *s)
{
    DWORD rv;

    /*
     * Cancelling the service on Windows is unfortunately complicated,
     * but that seems to be the Windows way.  If the registration
     * report is not already done, then we cancel it first.  The
     * cancel, is unfortunately, synchronous, so we must release the
     * lock, but that should be safe here, and we are waiting on a
     * non-blocking callback so that's not going to be an issue.
     *
     * There is a race here, we can still call cancel if the
     * registration is just being called, but that's ok, as the cancel
     * will return success and just not do anything.
     *
     * After that, we deregister.  If the service has been cancelled,
     * the registration callback will get called with an error, but it
     * still gets called, and that's all that matters.
     */

    if (!s->reported) {
	/*
	 * For some reason the cancel waits for the callback to be
	 * called, so we can't hold the lock here.
	 */
	gensio_mdns_unlock(s->m);
	rv = DnsServiceRegisterCancel(&s->cancel);
	gensio_mdns_lock(s->m);
	if (rv != ERROR_SUCCESS) {
	    int err = gensio_os_err_to_err(s->m->o, rv);

	    gensio_mdns_log(s->m, GENSIO_LOG_ERR,
			    "Error cancelling mdns service registration: %s",
			    gensio_err_to_str(err));
	}
    }

    rv = DnsServiceDeRegister(&s->dereq, NULL);
    if (rv != DNS_REQUEST_PENDING) {
	int err = gensio_os_err_to_err(s->m->o, rv);

	gensio_mdns_log(s->m, GENSIO_LOG_ERR,
			"Error deregistering mdns service registration: %s",
			gensio_err_to_str(err));
	enqueue_callback(s->m, &s->cbdata);
	s->cbdata.remove = true;
    }
}

#endif /* HAVE_AVAHI */

static void
free_service(struct gensio_os_funcs *o, struct gensio_mdns_service *s)
{
    struct gensio_mdns *m = s->m;

    if (s->link.list)
	gensio_list_rm(&m->services, &s->link);
    gensio_mdnslib_free_service(o, s);
    if (s->currname)
	gensio_cntstr_free(o, s->currname);
    if (s->name)
	o->free(o, s->name);
    if (s->type)
	o->free(o, s->type);
    if (s->domain)
	o->free(o, s->domain);
    if (s->host)
	o->free(o, s->host);
    o->free(o, s);
    gensio_mdns_deref(m);
}

static int
i_gensio_mdns_remove_service(struct gensio_mdns_service *s)
{
    s->removed = true;
    gensio_mdnslib_remove_service(s);

    return 0;
}

int
gensio_mdns_remove_service(struct gensio_mdns_service *s)
{
    struct gensio_mdns *m = s->m;
    int err;

    gensio_mdns_lock(m);
    err = i_gensio_mdns_remove_service(s);
    gensio_mdns_unlock(m);

    return err;
}

int
gensio_mdns_add_service2(struct gensio_mdns *m,
			 int ifinterface, int ipdomain,
			 const char *name, const char *type,
			 const char *domain, const char *host,
			 int port, const char * const *txt,
			 gensio_mdns_service_cb cb, void *cb_data,
			 struct gensio_mdns_service **rservice)
{
    struct gensio_os_funcs *o = m->o;
    struct gensio_mdns_service *s;
    int err = GE_NOMEM;

    if (!name || !type)
	return GE_INVAL;

    s = o->zalloc(m->o, sizeof(*s));
    if (!s)
	return GE_NOMEM;

    s->m = m;

    gensio_mdns_ref(m);
    s->port = port;
    s->name = gensio_strdup(o, name);
    if (!s->name)
	goto out_err;
    s->type = gensio_strdup(o, type);
    if (!s->type)
	goto out_err;
    if (dupstr(o, domain, &s->domain))
	goto out_err;
    if (dupstr(o, host, &s->host))
	goto out_err;

    err = gensio_cntstr_make(o, s->name, &s->currname);
    if (err)
	goto out_err;
    s->cb = cb;
    s->cb_data = cb_data;

    s->cbdata.s = s;

    err = gensio_mdnslib_initservice(s, ipdomain, ifinterface, txt);
    if (err)
	goto out_err;

    gensio_mdns_lock(m);
    gensio_list_add_tail(&m->services, &s->link);
    gensio_mdnslib_add_service(s);
    gensio_mdns_unlock(m);

    if (rservice)
	*rservice = s;

    return 0;

 out_err:
    gensio_mdns_lock(m);
    free_service(o, s);
    gensio_mdns_deref_and_unlock(m);
    return err;
}

int
gensio_mdns_add_service(struct gensio_mdns *m,
			int ifinterface, int ipdomain,
			const char *name, const char *type,
			const char *domain, const char *host,
			int port, const char * const *txt,
			struct gensio_mdns_service **rservice)
{
    return gensio_mdns_add_service2(m, ifinterface, ipdomain,
				    name, type, domain, host,
				    port, txt, NULL, NULL, rservice);
}

/*
 * MDNS lookups
 *
 * This code is pretty complicated.  For both Avahi and DNS-SD, there
 * is a three-stage process to get the results of a lookup.
 *
 * For Avahi, the first stage is to add a watch with the parameters
 * you want, which is an gensio_mdns_watch type.  This is done with
 * avahi_service_type_new().  The callback from that will have a MDNS
 * type.  Then a gensio_mdns_watch_browser is allocated for that type
 * and avahi_service_browser_new() is called with the new type.  It's
 * callback will be called with a name for each service of that type.
 * It then calls the mdns_browser_callback() common to all libraries,
 * which will allocate a gensio_mdns_watch_resolver type for final
 * resolution. In there that name is then resolved with
 * avahi_service_resolver_new(), which is called for each address for
 * the name, which has all the informaion for that service.
 *
 * DNS-SD is similar but different.  A watch is added as Avahi, with
 * DNSServiceBrowse().  That function, however, must have a type
 * supplied and it only reports names of that type.  There is no way
 * that I can find to browse for types.  So the first stack callback,
 * which uses the gensio_mdns_watch_browser type, has the name we are
 * looking for.  That callback then calls DNSServiceResolve() whose
 * callback reports a port and a hostname, but no addresses.  That
 * callback will call mdns_browser_callback(), which allocates a
 * resolver (with the port) and call DNSServiceGetAddrInfo() to
 * convert resolve the individual addresses.  The callbacks for that
 * will hvae the addresses we want, and those are reported to the
 * user.
 *
 * There are four tiers of data structures:
 *
 *   gensio_mdns_watch - created by gensio_mdns_add_watch(), the main
 *	watch structure.
 *
 *   gensio_mdns_watch_browser - created by
 *	avahi_service_type_callback() and dnssd_watch_callback(),
 *	callbacks from the main watdh.  A list of these is kept in
 *	gensio_mdns_watch.
 *
 *   gensio_mdns_watch_resolver - created by mdns_browser_callback(),
 *      which is called from avahi_service_browser_callback() and
 *      dnssd_service_callback(), callbacks from the watch browser
 *      callback.  A list of these is kept in
 *      gensio_mdns_watch_browser.
 *
 *   gensio_mdns_result - Holds the final results of the callbacks,
 *	one for each IP address from the query.  Created in
 *	mdns_resolver_callback().
 *
 * Windows works differently than Avahi and DNSMD, it actually works
 * more like the interface to this library.  There's one callback with
 * information.  However, to make it more compatible with this code,
 * it builds the whole type/browser structure artificially.
 */

struct gensio_mdns_result;

struct gensio_mdns_watch_data {
    struct gensio_mdns_result *result;

    enum gensio_mdns_data_state state;

    int ifinterface;
    int ipdomain;
    char *name;
    char *type;
    char *domain;
    char *host;
    struct gensio_addr *addr;
    const char **txt;
};

static void
gensio_mdns_free_watch_data(struct gensio_os_funcs *o,
			    struct gensio_mdns_watch_data *d)
{
    if (d->name)
	o->free(o, d->name);
    if (d->type)
	o->free(o, d->type);
    if (d->domain)
	o->free(o, d->domain);
    if (d->host)
	o->free(o, d->host);
    if (d->addr)
	gensio_addr_free(d->addr);
    if (d->txt)
	gensio_argv_free(o, d->txt);
    o->free(o, d);
}

struct gensio_mdns_watch_resolver;
struct gensio_mdns_result {
    struct gensio_link link;
    struct gensio_mdns_watch_resolver *resolver;
    struct gensio_mdns_callback cbdata;
    bool found;
    uint16_t port;
};

static void
result_free(struct gensio_os_funcs *o, struct gensio_mdns_result *e)
{
    if (e->cbdata.data)
	gensio_mdns_free_watch_data(o, e->cbdata.data);
    o->free(o, e);
}

struct gensio_mdns_watch_resolver {
    struct gensio_link link;
    struct gensio_mdns_watch_browser *b;
    int ifinterface;
    int protocol;
    uint16_t port; /* Not used for avahi. */
    char *host;
    char *name;
    char *type;
    char *domain;

    const char **txt; /* Not used for avahi. */

#if HAVE_AVAHI
    AvahiServiceResolver *avahi_resolver;
#endif

#if HAVE_DNSSD
    DNSServiceRef dnssd_sref;
#endif

    struct gensio_list results;
};

#if HAVE_WINMDNS
static struct gensio_mdns_result *
result_find(struct gensio_mdns_watch_resolver *r,
	    int ifinterface, int protocol,
	    const char *name, const char *type,
	    const char *domain, const char *host,
	    struct gensio_addr *addr, uint16_t port)
{
    struct gensio_mdns_result *e = NULL;
    struct gensio_link *l;

    gensio_list_for_each(&r->results, l) {
	e = gensio_container_of(l, struct gensio_mdns_result, link);

	if (e->cbdata.data->ifinterface == ifinterface &&
		e->cbdata.data->ipdomain == protocol &&
		gensio_addr_equal(e->cbdata.data->addr, addr, false, false) &&
		strcmp(e->cbdata.data->host, host) == 0 &&
		strcmp(e->cbdata.data->name, name) == 0 &&
		strcmp(e->cbdata.data->type, type) == 0 &&
		strcmp(e->cbdata.data->domain, domain) == 0)
	    break;
	else
	    e = NULL;
    }
    return e;
}
#endif

static void
result_remove(struct gensio_mdns *m,
	      struct gensio_mdns_watch_resolver *r,
	      struct gensio_mdns_result *e)
{
    gensio_list_rm(&r->results, &e->link);
    if (e->cbdata.in_queue) {
	if (e->cbdata.data->state == GENSIO_MDNS_WATCH_NEW_DATA) {
	    /* In queue but not reported, just remove it. */
	    gensio_list_rm(&m->callbacks, &e->cbdata.link);
	    gensio_mdns_deref(m);
	    result_free(m->o, e);
	}
	/* Otherwise already scheduled for removal. */
    } else {
	/* Report removal */
	e->cbdata.data->state = GENSIO_MDNS_WATCH_DATA_GONE;
	enqueue_callback(m, &e->cbdata);
    }
}

struct gensio_mdns_watch {
    struct gensio_link link;

    struct gensio_mdns *m;
    struct mdns_str_data name;
    struct mdns_str_data type;
    struct mdns_str_data domain;
    int ifinterface;
    int protocol;
    char *domainstr; /* Need this to kick things off. */
    char *typestr;
    struct mdns_str_data host;

#if HAVE_AVAHI
    AvahiServiceTypeBrowser *avahi_browser;

#elif HAVE_DNSSD
    DNSServiceRef dnssd_sref;

#elif HAVE_WINMDNS
    DNS_SERVICE_CANCEL winmdns_cancel;
#endif

    bool removed;

    unsigned int service_calls_pending;

    gensio_mdns_watch_cb cb;
    void *userdata;

    struct gensio_mdns_callback callback_data;

    gensio_mdns_watch_done remove_done;
    void *remove_done_data;

    struct gensio_list browsers;
};

static void
mdns_resolver_callback(struct gensio_mdns_watch_resolver *r,
		       struct gensio_mdns_watch *w,
		       enum gensio_mdns_data_state state,
		       int ifinterface, int protocol,
		       const char *name, const char *type,
		       const char *domain, const char *host,
		       struct gensio_addr *addr, uint16_t port,
		       const char **txt)
{
    struct gensio_mdns *m = w->m;
    struct gensio_mdns_callback *c = NULL;
    struct gensio_os_funcs *o = m->o;
    struct gensio_mdns_result *e;

    if (!mdns_str_cmp(&w->host, host))
	goto out_nomem;
    if (!mdns_str_cmp(&w->name, name))
	goto out_nomem;
    if (!mdns_str_cmp(&w->domain, domain))
	goto out_nomem;
    if (!mdns_str_cmp(&w->type, type))
	goto out_nomem;

    e = o->zalloc(o, sizeof(*e));
    if (!e)
	goto out_nomem;
    e->resolver = r;
    e->port = port;
    e->found = true;

    c = &e->cbdata;
    c->w = w;
    c->data = o->zalloc(o, sizeof(*(c->data)));
    if (!c->data)
	goto out_nomem;
    c->data->result = e;
    c->data->state = state;
    c->data->ifinterface = ifinterface;
    c->data->ipdomain = protocol;
    c->data->addr = addr;
    addr = NULL;
    c->data->txt = txt;
    txt = NULL;
    if (dupstr(o, name, &c->data->name))
	goto out_nomem;
    if (dupstr(o, type, &c->data->type))
	goto out_nomem;
    if (dupstr(o, domain, &c->data->domain))
	goto out_nomem;
    if (dupstr(o, host, &c->data->host))
	goto out_nomem;

    gensio_list_add_tail(&r->results, &e->link);
    enqueue_callback(m, c);
    return;

 out_nomem:
    if (addr)
	gensio_addr_free(addr);
    if (txt)
	gensio_argv_free(o, txt);
    if (c && c->data)
	gensio_mdns_free_watch_data(o, c->data);
}

struct gensio_mdns_watch_browser {
    struct gensio_link link;
    struct gensio_mdns_watch *w;
    int ifinterface;
    int protocol;
    char *name; /* Not used for avahi. */
    char *type;
    char *domain;

#if HAVE_AVAHI
    AvahiServiceBrowser *avahi_browser;
#endif

#if HAVE_DNSSD
    DNSServiceRef dnssd_sref;
#endif

    struct gensio_list resolvers;
};

static void browser_finish_one(struct gensio_mdns_watch *w);

#if HAVE_AVAHI

static void
gensio_mdnslib_reset_finish_one(struct gensio_mdns_watch *w)
{
}

static void
gensio_mdnslib_resolver_free(struct gensio_os_funcs *o,
			     struct gensio_mdns_watch_resolver *r)
{
    if (r->avahi_resolver)
	avahi_service_resolver_free(r->avahi_resolver);
}

/* Will be called with the lock held. */
static void
avahi_service_resolver_callback(AvahiServiceResolver *ar,
				AvahiIfIndex ainterface,
				AvahiProtocol aprotocol,
				AvahiResolverEvent event,
				const char *name,
				const char *type,
				const char *domain,
				const char *host,
				const AvahiAddress *a,
				uint16_t port,
				AvahiStringList *atxt,
				AvahiLookupResultFlags flags,
				void *userdata)
{
    struct gensio_mdns_watch_resolver *r = userdata;
    struct gensio_mdns_watch_browser *b = r->b;
    struct gensio_mdns_watch *w = b->w;
    struct gensio_mdns *m = w->m;
    struct gensio_os_funcs *o = m->o;
    struct gensio_addr *addr;
    int nettype, addrsize, rv, ifinterface;
    const void *addrdata = NULL;
    const char **txt = NULL;
    enum gensio_mdns_data_state state;
#ifdef AF_INET6
    struct sockaddr_in6 s6 = { .sin6_family = AF_INET6 };
#endif

    ifinterface = avahi_interface_to_interface(ainterface);

    switch (event) {
    case AVAHI_RESOLVER_FOUND:
	state = GENSIO_MDNS_NEW_DATA;
	break;

    case AVAHI_RESOLVER_FAILURE:
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error from resolver: %s",
			avahi_strerror(avahi_client_errno(m->ac)));
    default:
	return;
    }

    switch(a->proto) {
    case AVAHI_PROTO_INET:
	nettype = GENSIO_NETTYPE_IPV4;
	addrsize = sizeof(a->data.ipv4);
	addrdata = &a->data.ipv4;
	break;

#ifdef AF_INET6
    case AVAHI_PROTO_INET6:
	nettype = GENSIO_NETTYPE_IPV6;
	addrsize = sizeof(s6);
	addrdata = &s6;
	memcpy(&s6.sin6_addr, &a->data.ipv6, sizeof(s6.sin6_addr));
	if (IN6_IS_ADDR_LINKLOCAL(&s6.sin6_addr))
	    s6.sin6_scope_id = ifinterface;
	/* Port is not used here. */
	break;
#endif

    default:
	return;
    }

    if (gensio_addr_create(o, nettype, addrdata, addrsize, port, &addr))
	return;

    if (atxt) {
	gensiods args = 0, argc = 0;
	AvahiStringList *str;

	for (str = atxt; str; str = str->next) {
	    rv = gensio_argv_append(o, &txt, (char *) str->text,
				    &args, &argc, true);
	    if (rv)
		goto out;
	}
	rv = gensio_argv_append(o, &txt, NULL, &args, &argc, false);
	if (rv)
	    goto out;
    }

    mdns_resolver_callback(r, w, state, ifinterface, nettype, name, type,
			   domain, host, addr, port, txt);
    return;

 out:
    if (addr)
	gensio_addr_free(addr);
    if (txt)
	gensio_argv_free(o, txt);
}

static void
gensio_mdnslib_browser_free(struct gensio_os_funcs *o,
			    struct gensio_mdns_watch_browser *b)
{
    if (b->avahi_browser)
	avahi_service_browser_free(b->avahi_browser);
}

static int
gensio_mdnslib_start_resolver(struct gensio_mdns *m,
			      struct gensio_mdns_watch_resolver *r,
			      int ifinterface, int iprotocol,
			      const char *host, const char *type,
			      const char *domain,
			      int iaprotocol)
{
    int err;
    AvahiProtocol protocol;
    AvahiProtocol aprotocol;
    
    err = protocol_to_avahi_protocol(iprotocol, &protocol);
    if (err)
	return err;
    err = protocol_to_avahi_protocol(iaprotocol, &aprotocol);
    if (err)
	return err;

    r->avahi_resolver =
	avahi_service_resolver_new(m->ac, ifinterface, protocol,
				   host, type, domain, aprotocol,
				   0, avahi_service_resolver_callback,
				   r);
    if (!r->avahi_resolver)
	return GE_NOMEM;
    return 0;
}

#elif HAVE_DNSSD

static void
gensio_mdnslib_reset_finish_one(struct gensio_mdns_watch *w)
{
    /* We don't have to count these like avahi, just set it so it will finish */
    w->service_calls_pending = 1;
}

static void
gensio_mdnslib_resolver_free(struct gensio_os_funcs *o,
			     struct gensio_mdns_watch_resolver *r)
{
    DNSServiceRefDeallocate(r->dnssd_sref);
}

static void
gensio_mdnslib_browser_free(struct gensio_os_funcs *o,
			    struct gensio_mdns_watch_browser *b)
{
    DNSServiceRefDeallocate(b->dnssd_sref);
}

static void
dnssd_resolve_callback(DNSServiceRef sdRef,
		       DNSServiceFlags flags,
		       uint32_t interfaceIndex,
		       DNSServiceErrorType errorCode,
		       const char *hostname,
		       const struct sockaddr *address,
		       uint32_t ttl,
		       void *context)
{
    struct gensio_mdns_watch_resolver *r = context;
    struct gensio_mdns_watch_browser *b = r->b;
    struct gensio_mdns_watch *w = b->w;
    struct gensio_mdns *m = w->m;
    struct gensio_os_funcs *o = m->o;
    struct gensio_addr *addr = NULL;
    int nettype, rv, ifinterface;
    enum gensio_mdns_data_state state;
    char *host = NULL;
    const char **txt = NULL;

    if (errorCode) {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error from resolver: %d", errorCode);
	return;
    }

    ifinterface = dnssd_interface_to_interface(interfaceIndex);

    switch (address->sa_family) {
    case AF_INET: {
	struct sockaddr_in *addr4 = (struct sockaddr_in *) address;
	rv = gensio_addr_create(o, GENSIO_NETTYPE_IPV4,
				&addr4->sin_addr, sizeof(struct in_addr),
				r->port, &addr);
	nettype = GENSIO_NETTYPE_IPV4;
	break;
    }

    case AF_INET6: {
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) address;
	rv = gensio_addr_create(o, GENSIO_NETTYPE_IPV6,
				&addr6->sin6_addr, sizeof(struct in6_addr),
				r->port, &addr);
	nettype = GENSIO_NETTYPE_IPV6;
	break;
    }

    default:
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Unknown address type from resolver: %d",
			address->sa_family);
	goto out;
    }

    if (rv) {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error allocating resolver address: %s",
			gensio_err_to_str(rv));
	goto out;
    }

    host = dnssd_str_fix(o, hostname);
    if (!host) {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error allocating hostname: %s",
			gensio_err_to_str(GE_NOMEM));
	goto out;
    }
    if (r->txt) {
	rv = gensio_argv_copy(o, r->txt, NULL, &txt);
	if (rv) {
	    gensio_mdns_log(m, GENSIO_LOG_ERR,
			    "Error copying txt: %s", gensio_err_to_str(rv));
	    goto out;
	}
    }

    state = GENSIO_MDNS_NEW_DATA;
    mdns_resolver_callback(r, w, state, ifinterface, nettype, r->name, r->type,
			   r->domain, host, addr, r->port, txt);
 out:
    if (host)
	o->free(o, host);

    if (!(flags & kDNSServiceFlagsMoreComing))
	browser_finish_one(w);
}

static int
gensio_mdnslib_start_resolver(struct gensio_mdns *m,
			      struct gensio_mdns_watch_resolver *r,
			      int ifinterface, int protocol,
			      const char *host, const char *type,
			      const char *domain,
			      int iaprotocol)
{
    DNSServiceErrorType derr;
    uint32_t sinterface;
    DNSServiceProtocol sprotocol;
    int err;

    err = interface_to_dnssd_interface(ifinterface, &sinterface);
    if (err)
	return err;

    err = protocol_to_dnssd_protocol(protocol, &sprotocol);
    if (err)
	return err;

    r->dnssd_sref = m->dnssd_sref;
    derr = DNSServiceGetAddrInfo(&r->dnssd_sref,
				 kDNSServiceFlagsShareConnection,
				 sinterface, sprotocol, host,
				 dnssd_resolve_callback, r);
    if (derr)
	return dnssd_err_to_err(m, derr);

    return 0;
}

#elif defined(HAVE_WINMDNS)

static void
gensio_mdnslib_reset_finish_one(struct gensio_mdns_watch *w)
{
    /* We don't have to count these like avahi, just set it so it will finish */
    w->service_calls_pending = 1;
}

static void
gensio_mdnslib_resolver_free(struct gensio_os_funcs *o,
			     struct gensio_mdns_watch_resolver *r)
{
}

static void
gensio_mdnslib_browser_free(struct gensio_os_funcs *o,
			    struct gensio_mdns_watch_browser *b)
{
}

#endif /* HAVE_AVAHI */

static void browser_remove(struct gensio_mdns_watch_browser *b);
static void resolver_remove(struct gensio_mdns_watch_resolver *r);

static void
resolver_free(struct gensio_os_funcs *o, struct gensio_mdns_watch_resolver *r)
{
    gensio_mdnslib_resolver_free(o, r);
    if (r->host)
	o->free(o, r->host);
    if (r->name)
	o->free(o, r->name);
    if (r->type)
	o->free(o, r->type);
    if (r->domain)
	o->free(o, r->domain);
    if (r->txt)
	gensio_argv_free(o, r->txt);
    o->free(o, r);
}

static struct gensio_mdns_watch_resolver *
resolver_find(struct gensio_mdns_watch_browser *b,
	      int ifinterface, int protocol, int port,
	      const char *host, const char *name,
	      const char *type, const char *domain)
{
    struct gensio_mdns_watch_resolver *r = NULL;
    struct gensio_link *l;

    gensio_list_for_each(&b->resolvers, l) {
	r = gensio_container_of(l, struct gensio_mdns_watch_resolver, link);

	if (r->ifinterface == ifinterface && r->protocol == protocol &&
		(port == -1 || port == r->port) &&
		(host == NULL || strcmp(r->host, host) == 0) &&
		(name == NULL || strcmp(r->name, name) == 0) &&
		strcmp(r->type, type) == 0 &&
		strcmp(r->domain, domain) == 0)
	    break;
	else
	    r = NULL;
    }
    return r;
}

static void
resolver_remove(struct gensio_mdns_watch_resolver *r)
{
    struct gensio_mdns_watch_browser *b = r->b;
    struct gensio_mdns_watch *w = b->w;
    struct gensio_mdns *m = w->m;
    struct gensio_os_funcs *o = m->o;
    struct gensio_link *l, *l2;

    gensio_list_for_each_safe(&r->results, l, l2) {
	struct gensio_mdns_result *e =
	    gensio_container_of(l, struct gensio_mdns_result, link);

	result_remove(m, r, e);
    }
    gensio_list_rm(&b->resolvers, &r->link);
    resolver_free(o, r);
}

static void
browser_finish_one(struct gensio_mdns_watch *w)
{
    struct gensio_mdns *m = w->m;

    if (w->callback_data.all_for_now)
	return;

    assert(w->service_calls_pending > 0);
    w->service_calls_pending--;
    if (w->service_calls_pending == 0) {
	w->callback_data.all_for_now = true;
	enqueue_callback(m, &w->callback_data);
    }
}

static void
browser_free(struct gensio_os_funcs *o, struct gensio_mdns_watch_browser *b)
{
    gensio_mdnslib_browser_free(o, b);
    if (b->type)
	o->free(o, b->type);
    if (b->domain)
	o->free(o, b->domain);
    if (b->name)
	o->free(o, b->name);
    o->free(o, b);
}

#if !HAVE_WINMDNS
static void
mdns_browser_callback(struct gensio_mdns_watch_browser *b,
		      int ifinterface, int protocol, int port,
		      const char **txt, const char *host,
		      const char *name, const char *type, const char *domain)
{
    struct gensio_mdns_watch_resolver *r = NULL;
    struct gensio_mdns_watch *w = b->w;
    struct gensio_mdns *m = w->m;
    struct gensio_os_funcs *o = m->o;
    int err = GE_NOMEM;

    if (w->ifinterface != -1 && ifinterface != w->ifinterface)
	goto out;
    if (w->protocol != GENSIO_NETTYPE_UNSPEC && protocol != w->protocol)
	goto out;
    if (!mdns_str_cmp(&w->name, name))
	goto out;

    r = o->zalloc(o, sizeof(*r));
    if (!r)
	goto out_err;

    gensio_list_init(&r->results);
    r->b = b;
    r->ifinterface = ifinterface;
    r->protocol = protocol;
    r->port = port;
    r->txt = txt;
    txt = NULL;

    if (dupstr(o, host, &r->host))
	goto out_err;
    if (dupstr(o, name, &r->name))
	goto out_err;
    if (dupstr(o, type, &r->type))
	goto out_err;
    if (dupstr(o, domain, &r->domain))
	goto out_err;

    gensio_list_add_tail(&b->resolvers, &r->link);
    err = gensio_mdnslib_start_resolver(m, r, ifinterface, protocol,
					host, type, domain,
					w->protocol);
    if (err) {
	gensio_list_rm(&b->resolvers, &r->link);
	goto out_err;
    }
    return;

 out_err:
    gensio_mdns_log(m, GENSIO_LOG_ERR,
		    "Error allocating browser: %s", gensio_err_to_str(err));
    if (r)
	resolver_free(o, r);
 out:
    if (txt)
	gensio_argv_free(o, txt);
}
#endif

static struct gensio_mdns_watch_browser *
browser_find(struct gensio_mdns_watch *w,
	     int ifinterface, int protocol,
	     const char *name, const char *type, const char *domain)
{
    struct gensio_mdns_watch_browser *b;
    struct gensio_link *l;

    /* If we have the resolver set, remove it. */
    gensio_list_for_each(&w->browsers, l) {
	b = gensio_container_of(l, struct gensio_mdns_watch_browser, link);

	if (b->ifinterface == ifinterface && b->protocol == protocol &&
		(!name || strcmp(b->name, name) == 0) &&
		strcmp(b->type, type) == 0 &&
		strcmp(b->domain, domain) == 0)
	    return b;
    }
    return NULL;
}

static void
browser_remove(struct gensio_mdns_watch_browser *b)
{
    struct gensio_mdns_watch *w;
    struct gensio_link *l, *l2;

    if (!b)
	return;

    w = b->w;
    gensio_list_for_each_safe(&b->resolvers, l, l2) {
	struct gensio_mdns_watch_resolver *r =
	    gensio_container_of(l, struct gensio_mdns_watch_resolver,
				link);

	resolver_remove(r);
    }
    gensio_list_rm(&w->browsers, &b->link);
    browser_free(w->m->o, b);
}

#if HAVE_AVAHI

static void
avahi_service_browser_callback(AvahiServiceBrowser *ab,
			       AvahiIfIndex ainterface,
			       AvahiProtocol aprotocol,
			       AvahiBrowserEvent event,
			       const char *name,
			       const char *type,
			       const char *domain,
			       AvahiLookupResultFlags flags,
			       void *userdata)
{
    struct gensio_mdns_watch_browser *b = userdata;
    struct gensio_mdns_watch *w = b->w;
    struct gensio_mdns *m = w->m;
    struct gensio_mdns_watch_resolver *r = NULL;
    int protocol, ifinterface;

    ifinterface = avahi_interface_to_interface(ainterface);

    switch (event) {
    case AVAHI_BROWSER_NEW:
    case AVAHI_BROWSER_REMOVE:
	/* Handle this one below. */
	break;

    case AVAHI_BROWSER_ALL_FOR_NOW:
	browser_finish_one(w);
	return;

    case AVAHI_BROWSER_CACHE_EXHAUSTED:
    default:
	return;

    case AVAHI_BROWSER_FAILURE:
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error from browser: %s",
			avahi_strerror(avahi_client_errno(m->ac)));
	return;
    }

    if (avahi_protocol_to_protocol(aprotocol, &protocol))
	return;

    /* See if it aready exists. */
    r = resolver_find(b, ifinterface, protocol, -1, NULL, name, type, domain);

    if (event == AVAHI_BROWSER_REMOVE) {
	/* If we have the resolver, remove it. */
	if (r) {
	    resolver_remove(r);
	    if (gensio_list_empty(&b->resolvers))
		browser_remove(b);
	}
	return;
    }

    if (r)
	return; /* We already have it. */

    mdns_browser_callback(b, ifinterface, protocol, -1, NULL,
			  name, name, type, domain);
}

/* Will be called with the lock held. */
static void
avahi_service_type_callback(AvahiServiceTypeBrowser *ab,
			    AvahiIfIndex ainterface,
			    AvahiProtocol aprotocol,
			    AvahiBrowserEvent event,
			    const char *type,
			    const char *domain,
			    AvahiLookupResultFlags flags,
			    void *userdata)
{
    struct gensio_mdns_watch *w = userdata;
    struct gensio_mdns *m = w->m;
    struct gensio_os_funcs *o = m->o;
    struct gensio_mdns_watch_browser *b = NULL;
    int protocol, ifinterface, err;

    if (w->removed)
	return;

    ifinterface = avahi_interface_to_interface(ainterface);

    switch (event) {
    case AVAHI_BROWSER_NEW:
    case AVAHI_BROWSER_REMOVE:
	/* Handle this one below. */
	break;

    case AVAHI_BROWSER_ALL_FOR_NOW:
	browser_finish_one(w);
	return;

    case AVAHI_BROWSER_CACHE_EXHAUSTED:
    default:
	return;

    case AVAHI_BROWSER_FAILURE:
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error from type browser: %s",
			avahi_strerror(avahi_client_errno(m->ac)));
	return;
    }

    err = avahi_protocol_to_protocol(aprotocol, &protocol);
    if (err)
	return;

    b = browser_find(w, ifinterface, protocol, NULL, type, domain);

    if (event == AVAHI_BROWSER_REMOVE) {
	if (b)
	    browser_remove(b);
	return;
    }
    if (b)
	return; /* We already have it. */

    if (w->ifinterface != -1 && ifinterface != w->ifinterface)
	return;
    if (w->protocol != GENSIO_NETTYPE_UNSPEC && protocol != w->protocol)
	return;
    if (!mdns_str_cmp(&w->type, type))
	return;
    if (!mdns_str_cmp(&w->domain, domain))
	return;

    b = o->zalloc(o, sizeof(*b));
    if (!b)
	goto out_err;

    gensio_list_init(&b->resolvers);
    b->w = w;
    b->ifinterface = ifinterface;
    b->protocol = protocol;

    if (dupstr(o, type, &b->type))
	goto out_err;
    if (dupstr(o, domain, &b->domain))
	goto out_err;

    gensio_list_add_tail(&w->browsers, &b->link);
    w->service_calls_pending++;
    b->avahi_browser =
	avahi_service_browser_new(m->ac, ainterface, aprotocol,
				  type, domain,
				  0, avahi_service_browser_callback,
				  b);
    if (!b->avahi_browser) {
	gensio_list_rm(&w->browsers, &b->link);
	w->service_calls_pending--;
	goto out_err;
    }
    return;

 out_err:
    gensio_mdns_log(m, GENSIO_LOG_ERR,
		    "Out of memory allocating service type browser");
    if (b)
	browser_free(o, b);
}

static int
gensio_mdnslib_add_watch(struct gensio_mdns_watch *w)
{
    struct gensio_mdns *m = w->m;
    AvahiProtocol aprotocol;
    AvahiIfIndex ainterface;
    int err;

    err = protocol_to_avahi_protocol(w->protocol, &aprotocol);
    if (err)
	return GE_INVAL;

    if (m->state != AVAHI_CLIENT_S_RUNNING)
	/* This will be caught later when avahi is ready. */
	return 0;

    ainterface = interface_to_avahi_interface(w->ifinterface);

    w->avahi_browser =
	avahi_service_type_browser_new(m->ac, ainterface,
				       aprotocol, w->domainstr, 0,
				       avahi_service_type_callback, w);
    if (w->avahi_browser)
	w->service_calls_pending++;
    else
	return GE_NOMEM;

    return 0;
}

static void
gensio_mdnslib_watch_free(struct gensio_mdns_watch *w)
{
    if (w->avahi_browser)
	avahi_service_type_browser_free(w->avahi_browser);
    enqueue_callback(w->m, &w->callback_data);
    w->callback_data.remove = true;
}

#elif HAVE_DNSSD

static void
dnssd_service_callback(DNSServiceRef sdRef,
		       DNSServiceFlags flags,
		       uint32_t interfaceIndex,
		       DNSServiceErrorType errorCode,
		       const char *fullname,
		       const char *hosttarget,
		       uint16_t port, /* In network byte order */
		       uint16_t txtLen,
		       const unsigned char *txtRecord,
		       void *context)
{
    struct gensio_mdns_watch_browser *b = context;
    struct gensio_mdns_watch *w = b->w;
    struct gensio_mdns *m = w->m;
    struct gensio_os_funcs *o = m->o;
    struct gensio_mdns_watch_resolver *r = NULL;
    int ifinterface, rv = 0;
    const char **txt = NULL;
    char *host = NULL;

    port = ntohs(port);

    if (errorCode) {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error from service: %d", errorCode);
	return;
    }

    ifinterface = dnssd_interface_to_interface(interfaceIndex);

    host = dnssd_str_fix(o, hosttarget);
    if (!host)
	goto out_err;

    /* See if it aready exists. */
    r = resolver_find(b, ifinterface, b->protocol, port, host, NULL, b->type,
		      b->domain);

    if (!r) {
	/* One means no records. */
	if (txtRecord && txtLen > 1) {
	    gensiods args = 0, argc = 0;
	    const unsigned char *str;
	    uint8_t len;

	    for (str = txtRecord; str - txtRecord < txtLen; str += len) {
		len = *str;

		str++;
		if (str - txtRecord + len > txtLen) {
		    rv = GE_INVAL;
		    goto out_err;
		}
		rv = gensio_argv_nappend(o, &txt, (char *) str, len,
					 &args, &argc, true);
		if (rv)
		    goto out_err;
	    }
	    rv = gensio_argv_append(o, &txt, NULL, &args, &argc, false);
	    if (rv)
		goto out_err;
	}

	mdns_browser_callback(b, ifinterface, b->protocol, port, txt,
			      host, b->name, b->type, b->domain);
    }
    goto out;

 out_err:
    gensio_mdns_log(m, GENSIO_LOG_ERR,
		    "Out of memory processing txt string");
    if (txt)
	gensio_argv_free(o, txt);
 out:
    if (host)
	o->free(o, host);

    if (!(flags & kDNSServiceFlagsMoreComing))
	browser_finish_one(w);
}

static void
dnssd_watch_callback(DNSServiceRef sdRef,
		     DNSServiceFlags flags,
		     uint32_t interfaceIndex,
		     DNSServiceErrorType errorCode,
		     const char *name,
		     const char *itype,
		     const char *idomain,
		     void *context)
{
    struct gensio_mdns_watch *w = context;
    struct gensio_mdns *m = w->m;
    struct gensio_os_funcs *o = m->o;
    struct gensio_mdns_watch_browser *b = NULL;
    DNSServiceErrorType derr;
    int ifinterface, err = 0;
    char *type = NULL;
    char *domain = NULL;

    if (w->removed)
	return;

    if (errorCode) {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error from browse: %d", errorCode);
	return;
    }

    ifinterface = dnssd_interface_to_interface(interfaceIndex);

    err = GE_NOMEM;
    type = dnssd_str_fix(o, itype);
    if (!type)
	goto out_err;
    domain = dnssd_str_fix(o, idomain);
    if (!domain)
	goto out_err;

    b = browser_find(w, ifinterface, w->protocol, name, type, domain);

    if (!(flags & kDNSServiceFlagsAdd)) {
	if (b)
	    browser_remove(b);
	goto out;
    }
    if (b)
	goto out; /* We already have it. */

    if (w->ifinterface != -1 && ifinterface != w->ifinterface)
	goto out;
    if (!mdns_str_cmp(&w->name, name))
	goto out;
    if (!mdns_str_cmp(&w->type, type))
	goto out;
    if (!mdns_str_cmp(&w->domain, domain))
	goto out;

    b = o->zalloc(o, sizeof(*b));
    if (!b)
	goto out_err;

    gensio_list_init(&b->resolvers);
    b->w = w;
    b->ifinterface = ifinterface;
    b->protocol = w->protocol;

    if (dupstr(o, name, &b->name))
	goto out_err;
    if (dupstr(o, type, &b->type))
	goto out_err;
    if (dupstr(o, domain, &b->domain))
	goto out_err;

    gensio_list_add_tail(&w->browsers, &b->link);

    b->dnssd_sref = m->dnssd_sref;
    derr = DNSServiceResolve(&b->dnssd_sref, kDNSServiceFlagsShareConnection,
			     interfaceIndex, name, itype, idomain,
			     dnssd_service_callback, b);
    if (derr) {
	err = dnssd_err_to_err(m, derr);
	gensio_list_rm(&w->browsers, &b->link);
	goto out_err;
    }
    goto out;

 out_err:
    gensio_mdns_log(m, GENSIO_LOG_ERR,
		    "Error allocating service type browser: %s",
		    gensio_err_to_str(err));
    if (b)
	browser_free(o, b);
 out:
    if (type)
	o->free(o, type);
    if (domain)
	o->free(o, domain);

    if (!(flags & kDNSServiceFlagsMoreComing))
	browser_finish_one(w);
}

static int
gensio_mdnslib_add_watch(struct gensio_mdns_watch *w)
{
    struct gensio_mdns *m = w->m;
    DNSServiceErrorType derr;
    uint32_t sinterface;
    char *typestr = w->typestr;
    char *domainstr = w->domainstr;
    int err;

    if (!typestr) {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Attempt to add a watch with mdnssd without type");
	return GE_INCONSISTENT;
    } else if (*typestr == '@' || *typestr == '%') {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
	   "Attempt to add a watch with DNSSD with a glob or regex type");
	return GE_INCONSISTENT;
    } else if (domainstr && (*domainstr == '@' || *domainstr == '%')) {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
	   "Attempt to add a watch with DNSSD with a glob or regex domain");
	return GE_INCONSISTENT;
    }

    err = interface_to_dnssd_interface(w->ifinterface, &sinterface);
    if (err)
	return err;

    w->dnssd_sref = m->dnssd_sref;
    derr = DNSServiceBrowse(&w->dnssd_sref, kDNSServiceFlagsShareConnection,
			    sinterface, typestr, domainstr,
			    dnssd_watch_callback, w);
    if (derr) {
	err = dnssd_err_to_err(m, derr);
	return err;
    }

    return 0;
}

static void
gensio_mdnslib_watch_free(struct gensio_mdns_watch *w)
{
    DNSServiceRefDeallocate(w->dnssd_sref);
    enqueue_callback(w->m, &w->callback_data);
    w->callback_data.remove = true;
}

#elif HAVE_WINMDNS

static void WINAPI
win_browse_query_complete(void *context,
			  DNS_QUERY_RESULT *bres)
{
    struct gensio_mdns_watch *w = context;
    struct gensio_mdns *m = w->m;
    struct gensio_os_funcs *o = m->o;
    struct gensio_mdns_watch_browser *b = NULL;
    struct gensio_mdns_watch_resolver *r = NULL;
    struct gensio_mdns_result *e;
    struct gensio_link *l, *l2;
    DNS_RECORD *rec;
    char *name = NULL;
    char *host = NULL;
    char *domain = NULL; /* Points to something in name. */
    char *dot;
    const char **txt = NULL;
    uint16_t port = 0;
    DWORD rv;
    int err = 0;

    gensio_mdns_lock(m);
    if (bres->QueryStatus == ERROR_CANCELLED) {
	enqueue_callback(m, &w->callback_data);
	w->callback_data.remove = true;
	goto out_unlock;
    }
    if (w->removed)
	goto out_unlock;
    if (bres->QueryStatus != ERROR_SUCCESS) {
	err = gensio_os_err_to_err(o, bres->QueryStatus);
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Error from browse: %s (%d)", gensio_err_to_str(err),
			bres->QueryStatus);
	goto out_unlock;
    }

    /*
     * The first run through we extract the name, host, domain, and
     * txt.  We will handle A and AAAA records in the next run.
     */
    for (rec = bres->pQueryRecords; rec; rec = rec->pNext) {
        switch (rec->wType) {
        case DNS_TYPE_PTR:
	    /*
	     * Extract the service name from the string.  Format is like:
	     *
	     *   name._srv._tcp.local
	     *
	     * We have to search back through the '.'s to get the values.
	     * Also extract the domain as part of this.
	     */
	    if (name) /* Did we already get this? */
		break;
	    err = wchar_to_str(o, (wchar_t *) rec->Data.PTR.pNameHost, &name);
	    if (err)
		goto out_err;
	    dot = strrchr(name, '.');
	    if (!dot) {
		err = GE_INVAL;
		goto out_err;
	    }
	    domain = dot + 1;
	    if (dot == name) {
		err = GE_INVAL;
		goto out_err;
	    }
	    *dot = '\0';
	    dot = strrchr(name, '.');
	    if (!dot || dot == name) {
		err = GE_INVAL;
		goto out_err;
	    }
	    *dot = '\0';
	    dot = strrchr(name, '.');
	    if (!dot || dot == name) {
		err = GE_INVAL;
		goto out_err;
	    }
	    *dot = '\0';
            break;

        case DNS_TYPE_SRV:
	    /*
	     * Get the hostname here.  Have to remove the domain.
	     */
	    if (host) /* Did we already get this? */
		break;
	    err = wchar_to_str(o, (wchar_t *) rec->Data.SRV.pNameTarget,
			       &host);
	    if (err)
		goto out_err;
	    dot = strrchr(host, '.');
	    if (!dot) {
		err = GE_INVAL;
		goto out_err;
	    }
	    *dot = '\0';
	    port = rec->Data.SRV.wPort;
            break;

        case DNS_TYPE_TEXT:
	    if (txt) /* Did we already get this? */
		break;
            if (rec->Data.TXT.dwStringCount < 1)
                break;
            if (rec->Data.TXT.dwStringCount == 1 &&
                ((wchar_t *) (rec->Data.TXT.pStringArray[0]))[0] == 0) {
                break;
            }
	    err = wstring_array_to_argv(o, rec->Data.TXT.dwStringCount,
			(wchar_t **) rec->Data.TXT.pStringArray, &txt);
	    if (err)
		goto out_err;
            break;

        default:
            break;
        }
    }

    /* We have to get these from the results. */
    if (!name || !host || port == 0) {
	/* No need to check domain, it comes with name. */
	err = GE_INVAL;
	goto out_err;
    }

    err = GE_NOMEM;
    b = browser_find(w, w->ifinterface, w->protocol, NULL, w->typestr, domain);
    if (!b) {
	b = o->zalloc(o, sizeof(*b));
	if (!b)
	    goto out_err;

	gensio_list_init(&b->resolvers);
	b->w = w;
	b->ifinterface = w->ifinterface;
	b->protocol = w->protocol;

	if (dupstr(o, w->typestr, &b->type))
	    goto out_err;
	if (dupstr(o, domain, &b->domain))
	    goto out_err;

	gensio_list_add_tail(&w->browsers, &b->link);
    }

    r = resolver_find(b, w->ifinterface, w->protocol, -1, NULL,
		      name, w->typestr, domain);
    if (!r) {
	r = o->zalloc(o, sizeof(*r));
	if (!r)
	    goto out_err;

	gensio_list_init(&r->results);
	r->b = b;
	r->ifinterface = w->ifinterface;
	r->protocol = w->protocol;
	r->port = port;
	if (txt) {
	    err = gensio_argv_copy(o, txt, NULL, &r->txt);
	    if (err)
		goto out_err;
	}

	if (dupstr(o, host, &r->host))
	    goto out_err;
	if (dupstr(o, name, &r->name))
	    goto out_err;
	if (dupstr(o, w->typestr, &r->type))
	    goto out_err;
	if (dupstr(o, domain, &r->domain))
	    goto out_err;

	gensio_list_add_tail(&b->resolvers, &r->link);
    }

    gensio_list_for_each(&r->results, l) {
	e = gensio_container_of(l, struct gensio_mdns_result, link);
	e->found = false;
    }

    /* Now we get the A and AAAA records. */
    for (rec = bres->pQueryRecords; rec; rec = rec->pNext) {
        switch (rec->wType) {
        case DNS_TYPE_A: {
	    struct sockaddr_in in;
	    DWORD ifidx;
	    struct gensio_addr *addr;
	    const char **txt2 = NULL;

	    if (w->protocol != GENSIO_NETTYPE_IPV4 &&
			w->protocol != GENSIO_NETTYPE_UNSPEC)
		break;

	    memset(&in, 0, sizeof(in));
	    in.sin_family = AF_INET;
	    in.sin_port = port;
	    memcpy(&in.sin_addr, &rec->Data.A.IpAddress, sizeof(in.sin_addr));
	    /* Why doesn't windows pass this in? */
	    rv = GetBestInterfaceEx((struct sockaddr *) &in, &ifidx);
	    if (rv != ERROR_SUCCESS)
		break;

	    err = gensio_addr_create(o, GENSIO_NETTYPE_IPV4, &in.sin_addr,
				     sizeof(in.sin_addr), port, &addr);
	    if (err)
		break;

	    e = result_find(r, ifidx, GENSIO_NETTYPE_IPV4,
			    name, w->typestr, domain, host, addr, port);
	    if (e) {
		e->found = true;
		gensio_addr_free(addr);
		break;
	    }
	    if (txt) {
		err = gensio_argv_copy(o, r->txt, NULL, &txt2);
		if (err) {
		    gensio_addr_free(addr);
		    break;
		}
	    }
	    mdns_resolver_callback(r, w, GENSIO_MDNS_NEW_DATA,
				   ifidx, GENSIO_NETTYPE_IPV4,
				   name, w->typestr, domain, host, addr,
				   port, txt2);
	}
#ifdef AF_INET6
	case DNS_TYPE_AAAA: {
	    struct sockaddr_in6 in6;
	    DWORD ifidx;
	    struct gensio_mdns_result *e;
	    struct gensio_addr *addr;
	    const char **txt2 = NULL;

	    if (w->protocol != GENSIO_NETTYPE_IPV6 &&
			w->protocol != GENSIO_NETTYPE_UNSPEC)
		break;

	    memset(&in6, 0, sizeof(in6));
	    in6.sin6_family = AF_INET6;
	    in6.sin6_port = port;
	    memcpy(&in6.sin6_addr, &rec->Data.AAAA.Ip6Address,
		   sizeof(in6.sin6_addr));
	    /* Why doesn't windows pass this in? */
	    rv = GetBestInterfaceEx((struct sockaddr *) &in6, &ifidx);
	    if (rv != ERROR_SUCCESS)
		break;
	    in6.sin6_scope_id = ifidx;

	    err = gensio_addr_create(o, GENSIO_NETTYPE_IPV6, &in6,
				     sizeof(in6), port, &addr);
	    if (err)
		break;

	    e = result_find(r, ifidx, GENSIO_NETTYPE_IPV6,
			    name, w->typestr, domain, host, addr, port);
	    if (e) {
		e->found = true;
		gensio_addr_free(addr);
		break;
	    }
	    if (txt) {
		err = gensio_argv_copy(o, txt, NULL, &txt2);
		if (err) {
		    gensio_addr_free(addr);
		    break;
		}
	    }
	    mdns_resolver_callback(r, w, GENSIO_MDNS_NEW_DATA,
				   ifidx, GENSIO_NETTYPE_IPV6,
				   name, w->typestr, domain, host, addr,
				   port, txt2);
            break;
	}
#endif
        default:
            break;
        }
    }

    gensio_list_for_each_safe(&r->results, l, l2) {
	e = gensio_container_of(l, struct gensio_mdns_result, link);
	if (!e->found)
	    result_remove(m, r, e);
    }

 out_err:
    if (err)
	gensio_log(o, GENSIO_LOG_INFO, "Invalid mdns data: %s",
		   gensio_err_to_str(err));
    if (name)
	o->free(o, name);
    if (host)
	o->free(o, host);
    if (txt)
	gensio_argv_free(o, txt);

    if (r && gensio_list_empty(&r->results))
	resolver_remove(r);

    if (b && gensio_list_empty(&b->resolvers))
	browser_remove(b);

    if (!gensio_list_empty(&m->callbacks))
	browser_finish_one(w);

 out_unlock:
    if (bres->pQueryRecords)
	DnsRecordListFree(bres->pQueryRecords, DnsFreeRecordList);
    gensio_mdns_unlock(m);
}

static int
gensio_mdnslib_add_watch(struct gensio_mdns_watch *w)
{
    struct gensio_mdns *m = w->m;
    struct gensio_os_funcs *o = m->o;
    DNS_SERVICE_BROWSE_REQUEST breq;
    DNS_STATUS rv;
    char *tname = NULL;
    char *typestr = w->typestr;
    char *domainstr = w->domainstr;
    wchar_t *qname;
    int err;

    if (w->ifinterface == 0)
	return GE_INVAL;

    if (!typestr) {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
			"Attempt to add a watch with Windows MDNS without type");
	return GE_INCONSISTENT;
    } else if (*typestr == '@' || *typestr == '%') {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
	   "Attempt to add a watch with Windows MDNS with a glob or regex type");
	return GE_INCONSISTENT;
    } else if (domainstr && (*domainstr == '@' || *domainstr == '%')) {
	gensio_mdns_log(m, GENSIO_LOG_ERR,
	   "Attempt to add a watch with Windows MDNS with a glob or regex domain");
	return GE_INCONSISTENT;
    }

    memset(&breq, 0, sizeof(breq));

    if (!domainstr)
	domainstr = "local";

    tname = gensio_alloc_sprintf(o, "%s.%s", typestr, domainstr);
    if (!tname)
	return GE_NOMEM;

    err = str_to_wchar(o, tname, &qname);
    o->free(o, tname);
    if (err)
	return err;

    breq.Version = DNS_QUERY_REQUEST_VERSION2;
    if (w->ifinterface == -1)
	breq.InterfaceIndex = 0;
    else
	breq.InterfaceIndex = w->ifinterface;
    breq.QueryName = qname;
    breq.pBrowseCallbackV2 = win_browse_query_complete;
    breq.pQueryContext = w;

    rv = DnsServiceBrowse(&breq, &w->winmdns_cancel);
    if (rv != DNS_REQUEST_PENDING)
	err = gensio_os_err_to_err(o, rv);
    o->free(o, qname);
    return err;
}

static void
gensio_mdnslib_watch_free(struct gensio_mdns_watch *w)
{
    DnsServiceBrowseCancel(&w->winmdns_cancel);
}

#endif

static void
watch_free(struct gensio_os_funcs *o, struct gensio_mdns_watch *w)
{
    if (w->typestr)
	o->free(o, w->typestr);
    if (w->domainstr)
	o->free(o, w->domainstr);
    mdns_str_cleanup(o, &w->host);
    mdns_str_cleanup(o, &w->domain);
    mdns_str_cleanup(o, &w->type);
    mdns_str_cleanup(o, &w->name);
    o->free(o, w);
}

int
gensio_mdns_add_watch(struct gensio_mdns *m,
		      int ifinterface, int ipdomain,
		      const char *name, const char *type,
		      const char *domain, const char *host,
		      gensio_mdns_watch_cb callback, void *userdata,
		      struct gensio_mdns_watch **rwatch)
{
    struct gensio_mdns_watch *w;
    struct gensio_os_funcs *o = m->o;
    int err = GE_NOMEM;

    w = o->zalloc(o, sizeof(*w));
    if (!w)
	return GE_NOMEM;

    w->m = m;
    gensio_mdns_ref(m);
    w->cb = callback;
    w->callback_data.w = w;
    w->userdata = userdata;
    w->ifinterface = ifinterface;
    w->protocol = ipdomain;
    gensio_list_init(&w->browsers);
    gensio_mdnslib_reset_finish_one(w);

    err = mdns_str_setup(m, name, &w->name);
    if (err)
	goto out_err;
    err = mdns_str_setup(m, type, &w->type);
    if (err)
	goto out_err;
    err = mdns_str_setup(m, domain, &w->domain);
    if (err)
	goto out_err;
    err = mdns_str_setup(m, host, &w->host);
    if (err)
	goto out_err;

    /*
     * Windows and DNSSD need type set and can use domain, but they can't
     * be regexes or globs.  At least handle the '=' case for them.
     * These are not used for avahi.
     */
    if (domain && *domain == '=')
	domain++;
    if (type && *type == '=')
	type++;
    if (dupstr(o, domain, &w->domainstr))
	goto out_err;
    if (dupstr(o, type, &w->typestr))
	goto out_err;

    gensio_mdns_lock(m);
    gensio_list_add_tail(&m->watches, &w->link);
    err = gensio_mdnslib_add_watch(w);
    gensio_mdns_unlock(m);
    if (err) {
	gensio_list_rm(&m->watches, &w->link);
	goto out_err;
    }

    if (rwatch)
	*rwatch = w;
    return 0;

 out_err:
    gensio_mdns_lock(m);
    watch_free(o, w);
    gensio_mdns_deref_and_unlock(m);
    return err;
}

static int
i_gensio_mdns_remove_watch(struct gensio_mdns_watch *w,
			   gensio_mdns_watch_done done, void *userdata)
{
    struct gensio_mdns *m = w->m;
    struct gensio_os_funcs *o = m->o;
    struct gensio_link *l, *l2;
    struct gensio_link *li, *li2;
    struct gensio_link *lj, *lj2;
    struct gensio_mdns_watch_resolver *r;
    struct gensio_mdns_watch_browser *b;
    struct gensio_mdns_result *e;

    w->removed = true;
    w->remove_done = done;
    w->remove_done_data = userdata;
    gensio_list_rm(&m->watches, &w->link);

    gensio_list_for_each_safe(&w->browsers, l, l2) {
	b = gensio_container_of(l, struct gensio_mdns_watch_browser, link);

	gensio_list_for_each_safe(&b->resolvers, li, li2) {
	    r = gensio_container_of(li, struct gensio_mdns_watch_resolver,
				    link);
	    gensio_list_for_each_safe(&r->results, lj, lj2) {
		e = gensio_container_of(lj, struct gensio_mdns_result, link);
		if (e->cbdata.in_queue) {
		    gensio_list_rm(&m->callbacks, &e->cbdata.link);
		    gensio_mdns_deref(m);
		}
		gensio_list_rm(&r->results, &e->link);
		result_free(o, e);
	    }
	    gensio_list_rm(&b->resolvers, &r->link);
	    resolver_free(o, r);
	}
	gensio_list_rm(&w->browsers, &b->link);
	browser_free(o, b);
    }
    gensio_mdnslib_watch_free(w);

    return 0;
}

int
gensio_mdns_remove_watch(struct gensio_mdns_watch *w,
			 gensio_mdns_watch_done done, void *userdata)
{
    struct gensio_mdns *m = w->m;
    int err;

    gensio_mdns_lock(m);
    if (w->removed)
	err = GE_INUSE;
    else
	err = i_gensio_mdns_remove_watch(w, done, userdata);
    gensio_mdns_unlock(m);

    return err;
}

/*
 * Base allocation code
 *
 * A gensio_mdns structure is allocated here.  Both Avahi and DNS-SD
 * maintain a single file descriptor for all connections using this
 * allocated structure, though some special work has to be done with
 * DNS-SD to make this work.
 *
 * This structure will hold all running watches, which will point to
 * all running browsers, which will point to all running resolvers.
 */

#if HAVE_AVAHI

/* Lock should already be held when calling this. */
static void
avahi_client_callback(AvahiClient *ac, AvahiClientState state, void *userdata)
{
    struct gensio_mdns *m = userdata;
    struct gensio_link *l;
    struct gensio_mdns_service *s;
    struct gensio_mdns_watch *w;

    if (m->state == state)
	return;
    m->state = state;

    if (state == AVAHI_CLIENT_S_RUNNING) {
	gensio_list_for_each(&m->services, l) {
	    s = gensio_container_of(l, struct gensio_mdns_service, link);

	    gensio_mdnslib_add_service(s);
	}
	gensio_list_for_each(&m->watches, l) {
	    w = gensio_container_of(l, struct gensio_mdns_watch, link);

	    gensio_mdnslib_add_watch(w);
	}
    }
    /* FIXME - handle other states. */
}

int
gensio_mdnslib_start(struct gensio_mdns *m)
{
    int aerr;

    gensio_mdns_lock(m);
    m->ac = avahi_client_new(m->ap, AVAHI_CLIENT_NO_FAIL,
			     avahi_client_callback, m, &aerr);
    gensio_mdns_unlock(m);
    if (!m->ac) {
	gensio_log(m->o, GENSIO_LOG_ERR,
		   "mdns: Can't allocate avahi client: %s",
		   avahi_strerror(aerr));
	return GE_NOMEM;
    }
    return 0;
}

static void
gensio_mdnslib_disable(struct gensio_mdns *m)
{
    gensio_avahi_poll_disable(m->ap);
}

#elif HAVE_DNSSD

static void
dnssd_read_handler(struct gensio_iod *iod, void *cb_data)
{
    struct gensio_mdns *m = cb_data;

    gensio_mdns_lock(m);
    DNSServiceProcessResult(m->dnssd_sref);
    gensio_mdns_unlock(m);
}

static void
dnssd_except_handler(struct gensio_iod *iod, void *cb_data)
{
    dnssd_read_handler(iod, cb_data);
}

static void
dnssd_cleared_handler(struct gensio_iod *iod, void *cb_data)
{
    struct gensio_mdns *m = cb_data;

    gensio_mdns_lock(m);
    m->o->release_iod(m->iod);
    DNSServiceRefDeallocate(m->dnssd_sref);
    gensio_mdns_deref_and_unlock(m);
}

int
gensio_mdnslib_start(struct gensio_mdns *m)
{
    struct gensio_os_funcs *o = m->o;
    DNSServiceErrorType derr;
    int err;

    m->dnssd_fd = -1;

    derr = DNSServiceCreateConnection(&m->dnssd_sref);
    if (derr) {
	err = dnssd_err_to_err(m, derr);
	goto out_err;
    }

    m->dnssd_fd = DNSServiceRefSockFD(m->dnssd_sref);

    err = o->add_iod(o, GENSIO_IOD_SOCKET, m->dnssd_fd, &m->iod);
    if (err)
	goto out_err;

    err = o->set_fd_handlers(m->iod, m, dnssd_read_handler,
			     NULL, dnssd_except_handler,
			     dnssd_cleared_handler);
    if (err)
	goto out_err;

    gensio_mdns_ref(m);

    o->set_read_handler(m->iod, true);
    o->set_except_handler(m->iod, true);

    return 0;

 out_err:
    if (m->iod)
	o->clear_fd_handlers_norpt(m->iod);
    if (m->dnssd_fd != -1)
	DNSServiceRefDeallocate(m->dnssd_sref);
    return err;
}

static void
gensio_mdnslib_disable(struct gensio_mdns *m)
{
    m->o->clear_fd_handlers(m->iod);
}

#elif HAVE_WINMDNS

int
gensio_mdnslib_start(struct gensio_mdns *m)
{
    return 0;
}

static void
gensio_mdnslib_disable(struct gensio_mdns *m)
{
}

#endif

static void mdns_runner(struct gensio_runner *runner, void *userdata)
{
    struct gensio_mdns *m = userdata;
    struct gensio_os_funcs *o = m->o;
    struct gensio_link *l;
    struct gensio_mdns_callback *c;

    gensio_mdns_lock(m);
    while (!gensio_list_empty(&m->callbacks)) {
	l = gensio_list_first(&m->callbacks);
	c = gensio_container_of(l, struct gensio_mdns_callback, link);
	gensio_list_rm(&m->callbacks, &c->link);
	c->in_queue = false;
	gensio_mdns_deref(m);

	if (c->s) {
	    struct gensio_mdns_service *s = c->s;

	    if (c->remove) {
		if (s->cb) {
		    gensio_mdns_unlock(m);
		    s->cb(s, GENSIO_MDNS_SERVICE_REMOVED, NULL, s->cb_data);
		    gensio_mdns_lock(m);
		}
		free_service(m->o, s);
	    } else {
		enum gensio_mdns_service_event ev = GENSIO_MDNS_SERVICE_READY;

		if (c->namechange)
		    ev = GENSIO_MDNS_SERVICE_READY_NEW_NAME;
		c->namechange = false;
		c->all_for_now = false;
		if (s->cb) {
		    gensio_cntstr *str = gensio_cntstr_ref(o, s->currname);

		    gensio_mdns_unlock(m);
		    s->cb(s, ev, gensio_cntstr_get(str), s->cb_data);
		    gensio_mdns_lock(m);
		    gensio_cntstr_free(o, str);
		}
	    }
	} else if (c->w) {
	    struct gensio_mdns_watch *w = c->w;

	    if (c->remove) {
		if (w->remove_done) {
		    gensio_mdns_unlock(m);
		    w->remove_done(w, w->remove_done_data);
		    gensio_mdns_lock(m);
		}
		watch_free(o, w);
		gensio_mdns_deref(m);
	    } else {
		if (c->data) {
		    struct gensio_mdns_watch_data *d = c->data;
		    /*
		     * Store this, as d may be freed if it's not
		     * GENSIO_MDNS_WATCH_DATA_GONE.
		     */
		    enum gensio_mdns_data_state state = d->state;

		    if (!m->freed && !w->removed) {
			gensio_mdns_unlock(m);
			w->cb(w, d->state, d->ifinterface, d->ipdomain, d->name,
			      d->type, d->domain, d->host, d->addr, d->txt,
			      w->userdata);
			gensio_mdns_lock(m);
		    }
		    if (state == GENSIO_MDNS_WATCH_DATA_GONE)
			result_free(o, d->result);
		} else if (c->all_for_now) {
		    gensio_mdnslib_reset_finish_one(w);
		    c->all_for_now = false;
		    gensio_mdns_unlock(m);
		    w->cb(w, GENSIO_MDNS_WATCH_ALL_FOR_NOW, 0, 0, NULL,
			  NULL, NULL, NULL, NULL, NULL, w->userdata);
		    gensio_mdns_lock(m);
		}
	    }
	}
    }
    m->runner_pending = false;
    gensio_mdns_deref_and_unlock(m);
}

int
gensio_alloc_mdns(struct gensio_os_funcs *o, struct gensio_mdns **new_m)
{
    struct gensio_mdns *m;
    int err;

    m = o->zalloc(o, sizeof(*m));
    if (!m)
	return GE_NOMEM;

    m->o = o;
    m->refcount = 1;

    err = gensio_mdnslib_init(m);
    if (err) {
	o->free(o, m);
	return err;
    }

    m->runner = o->alloc_runner(o, mdns_runner, m);
    if (!m->runner) {
	gensio_mdnslib_free(m);
	return GE_NOMEM;
    }

    gensio_list_init(&m->services);
    gensio_list_init(&m->watches);
    gensio_list_init(&m->callbacks);

    err = gensio_mdnslib_start(m);
    if (err) {
	gensio_mdnslib_free(m);
	return err;
    }

    *new_m = m;
    return 0;
}

int
gensio_free_mdns(struct gensio_mdns *m, gensio_mdns_done done, void *userdata)
{
    struct gensio_os_funcs *o = m->o;
    struct gensio_link *l, *l2;
    int err = 0;

    gensio_mdns_lock(m);
    if (m->freed) {
	err = GE_INUSE;
	goto out_unlock;
    }

    gensio_mdnslib_disable(m);

    m->freed = true;
    m->free_done = done;
    m->free_userdata = userdata;

    gensio_list_for_each_safe(&m->callbacks, l, l2) {
	struct gensio_mdns_callback *c =
	    gensio_container_of(l, struct gensio_mdns_callback, link);

	if (c->remove)
	    /* Have to do the remove in the runner to avoid locking issues. */
	    continue;

	gensio_list_rm(&m->callbacks, &c->link);
	c->in_queue = false;
	gensio_mdns_deref(m);
	if (c->data && c->data->state == GENSIO_MDNS_WATCH_DATA_GONE)
	    result_free(o, c->data->result);
    }

    if (m->refcount == 1 && !m->runner_pending) {
	/*
	 * Run the runner to delete this.  Don't add a reference here,
	 * we want the runner to delete it.
	 */
	m->runner_pending = true;
	o->run(m->runner);
    } else {
	/*
	 * Services or watches are left or the runner is going to run,
	 * set it to be deleted in the runner after those are deleted.
	 */
	gensio_mdns_deref(m);
    }
 out_unlock:
    gensio_mdns_unlock(m);
    return err;
}

#else

int
gensio_alloc_mdns(struct gensio_os_funcs *o, struct gensio_mdns **m)
{
    return GE_NOTSUP;
}

int
gensio_free_mdns(struct gensio_mdns *m,
		 gensio_mdns_done done, void *userdata)
{
    return GE_NOTSUP;
}


int
gensio_mdns_add_service(struct gensio_mdns *m,
			int ifinterface, int ipdomain,
			const char *name, const char *type,
			const char *domain, const char *host,
			int port, const char * const *txt,
			struct gensio_mdns_service **rservice)
{
    return GE_NOTSUP;
}

int
gensio_mdns_add_service2(struct gensio_mdns *m,
			 int ifinterface, int ipdomain,
			 const char *name, const char *type,
			 const char *domain, const char *host,
			 int port, const char * const *txt,
			 gensio_mdns_service_cb cb, void *cb_data,
			 struct gensio_mdns_service **rservice)
{
    return GE_NOTSUP;
}

int
gensio_mdns_remove_service(struct gensio_mdns_service *s)
{
    return GE_NOTSUP;
}

int
gensio_mdns_add_watch(struct gensio_mdns *m,
		      int ifinterface, int ipdomain,
		      const char *name, const char *type,
		      const char *domain, const char *host,
		      gensio_mdns_watch_cb callback, void *userdata,
		      struct gensio_mdns_watch **rwatch)
{
    return GE_NOTSUP;
}

int
gensio_mdns_remove_watch(struct gensio_mdns_watch *w,
			 gensio_mdns_watch_done done, void *userdata)
{
    return GE_NOTSUP;
}

#endif
