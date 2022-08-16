/*
 * Copyright 2020 Corey Minyard
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <gensio/gensio.h>
#include <gensio/gensio_sound.h>
#include <../tools/utils.h>

#ifdef _WIN32
#define GENSIOSIG 0
#include <combaseapi.h>
#else
#define GENSIOSIG SIGUSR1
#endif

static struct gensio_os_funcs *o;
static int global_err;
static unsigned int channels = 1;
static unsigned char *playbuf;
static gensiods playbuf_size;
static gensiods playbuf_len;
static gensiods playbuf_pos;

static void
do_vlog(struct gensio_os_funcs *f, enum gensio_log_levels level,
	const char *log, va_list args)
{
    fprintf(stderr, "gensio %s log: ", gensio_log_level_to_str(level));
    vfprintf(stderr, log, args);
    fprintf(stderr, "\n");
}

static int
fill_playbuf(void)
{
    size_t i;

    i = fread(playbuf, playbuf_size, 1, stdin);
    if (i == 0)
	return GE_REMCLOSE;
    playbuf_len = playbuf_size;
    return 0;
}

static int
io_event(struct gensio *io, void *user_data, int event, int err,
	 unsigned char *buf, gensiods *buflen,
	 const char *const *auxdata)
{
    struct gensio_waiter *waiter = user_data;
    gensiods i;
    size_t len;

    switch (event) {
    case GENSIO_EVENT_READ:
	if (err)
	    goto handle_err;
	len = fwrite(buf, *buflen, 1, stdout);
	if (len == 0) {
	    err = GE_REMCLOSE;
	    goto handle_err;
	}
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	err = gensio_write(io, &i, playbuf + playbuf_pos,
			   playbuf_len, NULL);
	if (err)
	    goto handle_err;
	if (i >= playbuf_len) {
	    err = fill_playbuf();
	    if (err)
		goto handle_err;
	} else {
	    playbuf_pos += i;
	    playbuf_len -= i;
	}
	return 0;

    default:
	return GE_NOTSUP;
    }
 handle_err:
    gensio_set_read_callback_enable(io, false);
    gensio_set_write_callback_enable(io, false);
    if (err != GE_REMCLOSE) {
	fprintf(stderr, "Error from io: %s\n", gensio_err_to_str(err));
	global_err = err;
    }
    gensio_os_funcs_wake(o, waiter);
    return 0;
}

static int
list_sound_devs(const char *devtype)
{
    char **names, **specs;
    gensiods i, count;
    int err;

    /* FIXME - supply a sound type. */
    err = gensio_sound_devices(devtype, &names, &specs, &count);
    if (err) {
	fprintf(stderr, "Unable to get sound devices: %s\n",
		gensio_err_to_str(err));
	return 1;
    }

    printf("%-50s %s\n", "Name", "Specs");
    for (i = 0; i < count; i++)
	printf("%-50s %s\n", names[i], specs[i]);

    gensio_sound_devices_free(names, specs, count);
    return 0;
}

static void
term_handler(void *cb_data)
{
    struct gensio_waiter *waiter = cb_data;

    gensio_os_funcs_wake(o, waiter);
}

int
main(int argc, char *argv[])
{
    int rv, arg;
    struct gensio_os_proc_data *proc_data;
    unsigned int bufsize = 2048;
    unsigned int sample_rate = 44100;
    unsigned int num_bufs = 4;
    struct gensio *io;
    struct gensio_waiter *waiter;
    char *gensiostr;
    bool list_devs = false;
    bool play = false;
    const char *devtype = NULL; /* Take the default by default. */
    const char *format = "float";

    for (arg = 1; arg < argc; arg++) {
	if (argv[arg][0] != '-')
	    break;
	if (strcmp(argv[arg], "--") == 0) {
	    arg++;
	    break;
	}
	if ((rv = cmparg_uint(argc, argv, &arg, "-r", "--rate",
			      &sample_rate)))
	    ;
	else if ((rv = cmparg_uint(argc, argv, &arg, "-n", "--nbufs",
				   &num_bufs)))
	    ;
	else if ((rv = cmparg_uint(argc, argv, &arg, "-c", "--channels",
				   &channels)))
	    ;
	else if ((rv = cmparg_uint(argc, argv, &arg, "-s", "--bufsize",
				   &bufsize)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, "-t", "--type", &devtype)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, "-f", "--format", &format)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, "-p", "--play", NULL))) {
	    play = true;
	} else if ((rv = cmparg(argc, argv, &arg, "-L", "--list-devs", NULL))) {
	    list_devs = true;
	} else if ((rv = cmparg(argc, argv, &arg, "-d", "--debug", NULL))) {
	    gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	} else {
	    fprintf(stderr, "Unknown argument: %s\n", argv[arg]);
	    return 1;
	}
    }

    if (list_devs) {
	list_sound_devs(devtype);
	return 0;
    }

    if (arg >= argc) {
	fprintf(stderr, "No sound device given\n");
	return 1;
    }

    if (bufsize % (channels * 4) != 0) {
	fprintf(stderr, "bufsize must be a multiple of channel * 4\n");
	return 1;
    }

    gensiostr = alloc_sprintf("sound(rate=%u,%schans=%u,bufsize=%u,nbufs=%u,"
			      "format=%s%s%s),%s",
			      sample_rate, play ? "out" : "in",
			      channels, bufsize, num_bufs, format,
			      devtype ? ",type=" : "", devtype ? devtype : "",
			      argv[arg]);
    if (!gensiostr) {
	fprintf(stderr, "Could not allocate gensio string\n");
	return 1;
    }

    rv = gensio_default_os_hnd(GENSIOSIG, &o);
    if (rv) {
	free(gensiostr);
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    gensio_os_funcs_set_vlog(o, do_vlog);

    rv = gensio_os_proc_setup(o, &proc_data);
    if (rv) {
	free(gensiostr);
	fprintf(stderr, "Could not setup process data: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    waiter = gensio_os_funcs_alloc_waiter(o);
    if (!waiter) {
	free(gensiostr);
	rv = GE_NOMEM;
	fprintf(stderr, "Could not waiter, out of memory\n");
	goto out_err;
    }

    rv = str_to_gensio(gensiostr, o, io_event, waiter, &io);
    free(gensiostr);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", argv[arg],
		gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_open_s(io);
    if (rv) {
	fprintf(stderr, "Could not open %s: %s\n", argv[arg],
		gensio_err_to_str(rv));
	goto out_err;
    }

    if (play) {
	playbuf_size = bufsize;
	playbuf = malloc(bufsize);
	if (!playbuf) {
	    fprintf(stderr, "Unable to allocate output buffer\n");
	    rv = 1;
	    goto out_err;
	}
	rv = fill_playbuf();
	if (rv == GE_REMCLOSE) {
	    rv = 0;
	    goto out_err;
	}
	if (rv)
	    goto out_err;
	gensio_set_write_callback_enable(io, true);
    } else {
	gensio_set_read_callback_enable(io, true);
    }

    gensio_os_proc_register_term_handler(proc_data, term_handler, waiter);

    gensio_os_funcs_wait(o, waiter, 1, NULL);

    gensio_close_s(io);

    rv = global_err;

 out_err:
    if (waiter)
	gensio_os_funcs_free_waiter(o, waiter);
    gensio_os_proc_cleanup(proc_data);
    gensio_os_funcs_free(o);

    return !!rv;
}
