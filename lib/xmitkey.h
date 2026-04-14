/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2022  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This file holds transmitter keying handling.  It is in a separate
 * file so multiple gensios can use it.
 */

enum keytype {
    KEY_RW, /* Read and write keyon/keyoff values. */
    KEY_RTS,
    KEY_RTSINV,
    KEY_DTR,
    KEY_DTRINV,
    KEY_CM108
};

enum keystate {
    KEY_CLOSED,
    KEY_IN_OPEN,
    KEY_OPEN,
    KEY_IN_CLOSE,
};

struct keydata {
    const char *key;
    int keytype;
    unsigned int keybit;
    const char *keyon;
    const char *keyoff;
};

#define KEYDATA_INIT(v) \
    v.keytype = KEY_RW,		\
    v.keybit = 3,		\
    v.keyon = "T 1\n",		\
    v.keyoff = "T 0\n"

struct keyinfo {
    void (*report_key_log)(void *cb_data, enum gensio_log_levels level,
			   const char *fmt, ...);
    void (*open_done)(void *cb_data);
    void *cb_data;

    /* For reporting key errors. */
    struct gensio_pparm_info p;

    enum keytype keytype;
    struct gensio *key_io;
    char *key;
    char *keyon;
    char *keyoff;
    int key_err;
    bool keyed; /* Is the transmitter keyed? */
    enum keystate key_io_state;
};

static void
keyop_done(struct gensio *io, int err, const char *buf, gensiods len,
	   void *cb_data)
{
    struct keyinfo *keyinfo = cb_data;

    if (err)
	keyinfo->report_key_log(keyinfo->cb_data, GENSIO_LOG_WARNING,
				"afskmdm: Error keying transmitter: %s\n",
				gensio_err_to_str(err));
}

static void
key_do_keyon(struct keyinfo *keyinfo)
{
    int rv;

    if (keyinfo->keyed)
	return;
    if (!keyinfo->key_io)
	return;
    switch (keyinfo->keytype) {
    case KEY_RW:
	gensio_write(keyinfo->key_io, NULL,
		     keyinfo->keyon, strlen(keyinfo->keyon), NULL);
	break;

    case KEY_RTS:
	rv = gensio_acontrol(keyinfo->key_io, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_SET, GENSIO_ACONTROL_SER_RTS,
			     "on", 0, keyop_done, keyinfo, NULL);
	if (rv)
	    keyop_done(keyinfo->key_io, rv, NULL, 0, keyinfo);
	break;

    case KEY_RTSINV:
	rv = gensio_acontrol(keyinfo->key_io, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_SET, GENSIO_ACONTROL_SER_RTS,
			     "off", 0, keyop_done, keyinfo, NULL);
	if (rv)
	    keyop_done(keyinfo->key_io, rv, NULL, 0, keyinfo);
	break;

    case KEY_DTR:
	rv = gensio_acontrol(keyinfo->key_io, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_SET, GENSIO_ACONTROL_SER_DTR,
			     "on", 0, keyop_done, keyinfo, NULL);
	if (rv)
	    keyop_done(keyinfo->key_io, rv, NULL, 0, keyinfo);
	break;

    case KEY_DTRINV:
	rv = gensio_acontrol(keyinfo->key_io, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_SET, GENSIO_ACONTROL_SER_DTR,
			     "off", 0, keyop_done, keyinfo, NULL);
	if (rv)
	    keyop_done(keyinfo->key_io, rv, NULL, 0, keyinfo);
	break;

    case KEY_CM108: /* Should never happen. */
	assert(0);
    }
    keyinfo->keyed = true;
}

static void
key_do_keyoff(struct keyinfo *keyinfo)
{
    int rv;

    if (!keyinfo->keyed)
	return;
    switch (keyinfo->keytype) {
    case KEY_RW:
	gensio_write(keyinfo->key_io, NULL,
		     keyinfo->keyoff, strlen(keyinfo->keyoff), NULL);
	break;

    case KEY_RTS:
	rv = gensio_acontrol(keyinfo->key_io, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_SET, GENSIO_ACONTROL_SER_RTS,
			     "off", 0, keyop_done, keyinfo, NULL);
	if (rv)
	    keyop_done(keyinfo->key_io, rv, NULL, 0, keyinfo);
	break;

    case KEY_RTSINV:
	rv = gensio_acontrol(keyinfo->key_io, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_SET, GENSIO_ACONTROL_SER_RTS,
			     "on", 0, keyop_done, keyinfo, NULL);
	if (rv)
	    keyop_done(keyinfo->key_io, rv, NULL, 0, keyinfo);
	break;

    case KEY_DTR:
	rv = gensio_acontrol(keyinfo->key_io, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_SET, GENSIO_ACONTROL_SER_DTR,
			     "off", 0, keyop_done, keyinfo, NULL);
	if (rv)
	    keyop_done(keyinfo->key_io, rv, NULL, 0, keyinfo);
	break;

    case KEY_DTRINV:
	rv = gensio_acontrol(keyinfo->key_io, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_SET, GENSIO_ACONTROL_SER_DTR,
			     "on", 0, keyop_done, keyinfo, NULL);
	if (rv)
	    keyop_done(keyinfo->key_io, rv, NULL, 0, keyinfo);
	break;

    case KEY_CM108: /* Should never happen. */
	assert(0);
    }
    keyinfo->keyed = false;
}

static int
key_cb(struct gensio *io, void *user_data, int event, int err,
       unsigned char *buf, gensiods *buflen, const char *const *auxdata)
{
    struct keyinfo *keyinfo = user_data;

    switch(event) {
    case GENSIO_EVENT_READ:
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	return 0;

    case GENSIO_EVENT_PARMLOG: {
	struct gensio_parmlog_data *d = (struct gensio_parmlog_data *) buf;

	gensio_pparm_vlog(&keyinfo->p, d->log, d->args);
	return 0;
    }

    default:
	return GE_NOTSUP;
    }
}

static void
key_open_done(struct gensio *io, int err, void *open_data)
{
    struct keyinfo *keyinfo = open_data;

    if (err) {
	keyinfo->key_io_state = KEY_CLOSED;
	keyinfo->report_key_log(keyinfo->cb_data, GENSIO_LOG_ERR,
				"afskmdm: Error from open key I/O '%s': %s",
				keyinfo->key, gensio_err_to_str(err));
    } else {
	keyinfo->key_io_state = KEY_OPEN;
	/* Some keytypes come up on.  Make sure it's off. */
	keyinfo->keyed = true; /* Force keyoff to work. */
	key_do_keyoff(keyinfo);
    }
    keyinfo->key_err = err;

    /* Just turn on read and ignore what we get. */
    gensio_set_read_callback_enable(io, true);

    keyinfo->open_done(keyinfo->cb_data);
}

static int
key_try_open(struct keyinfo *keyinfo, gensio_time *timeout)
{
    int err;

    if (keyinfo->key_io &&
	keyinfo->key_io_state != KEY_IN_OPEN &&
	keyinfo->key_io_state != KEY_OPEN) {

	err = gensio_open(keyinfo->key_io, key_open_done, keyinfo);
	if (err) {
	    keyinfo->report_key_log(keyinfo->cb_data, GENSIO_LOG_ERR,
				    "afskmdm: Unable to open key I/O '%s': %s",
				    keyinfo->key, gensio_err_to_str(err));
	    return err;
	}
	keyinfo->key_io_state = KEY_IN_OPEN;
    }
    if (keyinfo->key_io_state == KEY_IN_OPEN) {
	timeout->secs = 0;
	timeout->nsecs = GENSIO_MSECS_TO_NSECS(10);
	return GE_RETRY;
    }
    return 0;
}

static void
key_close_done(struct gensio *io, void *close_data)
{
    struct keyinfo *keyinfo = close_data;

    keyinfo->key_io_state = KEY_CLOSED;
}

static int
key_try_close(struct keyinfo *keyinfo, gensio_time *timeout)
{
    int err;

    if (keyinfo->key_io_state == KEY_OPEN) {
	key_do_keyoff(keyinfo);
	err = gensio_close(keyinfo->key_io, key_close_done, keyinfo);
	if (err) {
	    keyinfo->key_io_state = KEY_CLOSED;
	    keyinfo->report_key_log(keyinfo->cb_data, GENSIO_LOG_WARNING,
				   "afskmdm: Error from close key I/O '%s': %s",
				   keyinfo->key, gensio_err_to_str(err));
	} else {
	    keyinfo->key_io_state = KEY_IN_CLOSE;
	}
    }
    if (keyinfo->key_io_state == KEY_IN_CLOSE) {
	timeout->secs = 0;
	timeout->nsecs = GENSIO_MSECS_TO_NSECS(10);
	return GE_RETRY;
    }
    return 0;
}

static void
key_cleanup(struct keyinfo *keyinfo)
{
    if (keyinfo->key_io)
	gensio_close(keyinfo->key_io, NULL, NULL);
    keyinfo->key_io_state = KEY_CLOSED;
    keyinfo->key_err = 0;
}

static void
key_free(struct keyinfo *keyinfo, struct gensio_os_funcs *o)
{
    if (keyinfo->key_io)
	gensio_free(keyinfo->key_io);
    if (keyinfo->key)
	o->free(o, keyinfo->key);
    if (keyinfo->keyon)
	o->free(o, keyinfo->keyon);
    if (keyinfo->keyoff)
	o->free(o, keyinfo->keyoff);
}

static int
key_setup(struct keyinfo *keyinfo, struct keydata *data, struct gensio *child,
	  struct gensio_os_funcs *o, struct gensio_pparm_info *p,
	  void (*open_done)(void *cb_data),
	  void (*report_key_log)(void *cb_data, enum gensio_log_levels level,
				 const char *fmt, ...),
	  void *cb_data)
{
    keyinfo->open_done = open_done;
    keyinfo->report_key_log = report_key_log;
    keyinfo->cb_data = cb_data;
    if (data->key) {
	keyinfo->key = gensio_strdup(o, data->key);
	if (!keyinfo->key)
	    return GE_NOMEM;
    }
    keyinfo->keytype = data->keytype;
    if (data->keyon) {
	keyinfo->keyon = gensio_strdup(o, data->keyon);
	if (!keyinfo->keyon)
	    return GE_NOMEM;
    }
    if (data->keyoff) {
	keyinfo->keyoff = gensio_strdup(o, data->keyoff);
	if (!keyinfo->keyoff)
	    return GE_NOMEM;
    }

    keyinfo->p = *p;

    if (keyinfo->keytype == KEY_CM108) {
	char name[100];
	gensiods len = sizeof(name);
	int err;

	strcpy(name, "out");
	err = gensio_control(child, 0, true, GENSIO_CONTROL_LADDR, name, &len);
	if (err) {
	    gensio_pparm_log(p, "Unable to get the output sound card name for"
			     " fetching the cm108 parameter: %s.",
			     gensio_err_to_str(err));
	    return GE_NOMEM;
	}
	if (keyinfo->key)
	    o->free(o, keyinfo->key);
	keyinfo->keytype = KEY_RW;
	keyinfo->key = gensio_alloc_sprintf(o, "cm108gpio(bit=%u),%s",
					    data->keybit, name);
	if (!keyinfo->key)
	    return GE_NOMEM;
    }
    if (keyinfo->key) {
	int err = str_to_gensio(keyinfo->key, o, key_cb, keyinfo,
				&keyinfo->key_io);
	if (err) {
	    gensio_pparm_log(p, "Could not allocate key gensio '%s': %s",
			     keyinfo->key, gensio_err_to_str(err));
	    return GE_NOMEM;
	}
	switch (keyinfo->keytype) {
	case KEY_RTS: case KEY_RTSINV: case KEY_DTR: case KEY_DTRINV:
	    if (!gensio_is_serial(keyinfo->key_io)) {
		gensio_pparm_log(p, "A serial keytype was given, '%s',"
				 " but it is not a serial gensio",
				 keyinfo->key);
		return GE_NOMEM;
	    }
	    break;

	default:
	    break;
	}
    }

    return 0;
}

static struct gensio_enum_val keytype_enums[] = {
    { .name = "rw", .val = KEY_RW },
    { .name = "rts", .val = KEY_RTS },
    { .name = "rtsinv", .val = KEY_RTSINV },
    { .name = "dtr", .val = KEY_DTR },
    { .name = "dtrinv", .val = KEY_DTRINV },
    { .name = "cm108", .val = KEY_CM108 },
    { }
};

static int
key_pparm(struct gensio_pparm_info *p, const char *arg, struct keydata *data)
{
    if (gensio_pparm_value(p, arg, "key", &data->key) > 0)
	return 1;
    if (gensio_pparm_enum(p, arg, "keytype", keytype_enums,
			  &data->keytype) > 0)
	return 1;
    if (gensio_pparm_uint(p, arg, "keybit", &data->keybit) > 0)
	return 1;
    if (gensio_pparm_value(p, arg, "keyon", &data->keyon) > 0)
	return 1;
    if (gensio_pparm_value(p, arg, "keyoff", &data->keyoff) > 0)
	return 1;
    return 0;
}
