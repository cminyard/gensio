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
#include <gensio/gensio_osops.h>
#include "utils.h"

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
FILE *infile;
FILE *outfile;

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

    i = fread(playbuf, playbuf_size, 1, infile);
    if (i == 0)
	return GE_REMCLOSE;
    playbuf_len = playbuf_size;
    playbuf_pos = 0;
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
	len = fwrite(buf, *buflen, 1, outfile);
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
list_sound_devs(struct gensio_os_funcs *o, const char *devtype)
{
    char *gstr;
    struct gensio *lg;
    char buf[1025];
    gensiods len;
    int err;

    if (devtype)
	gstr = alloc_sprintf("sound(list,type=%s)", devtype);
    else
	gstr = alloc_sprintf("sound(list)");
    if (!gstr) {
	fprintf(stderr, "Unable to allocate gensio string\n");
	return 1;
    }
    err = str_to_gensio(gstr, o, NULL, NULL, &lg);
    free(gstr);
    if (err) {
	fprintf(stderr, "Unable to allocated gensio: %s\n",
		gensio_err_to_str(err));
	return 1;
    }

    err = gensio_open_s(lg);
    if (err) {
	fprintf(stderr, "Unable to open gensio: %s\n",
		gensio_err_to_str(err));
	return 1;
    }

    err = gensio_set_sync(lg);
    if (err) {
	fprintf(stderr, "Unable to set gensio sync: %s\n",
		gensio_err_to_str(err));
	return 1;
    }

    do {
	err = gensio_read_s(lg, &len, buf, sizeof(buf) - 1, NULL);
	if (!err) {
	    buf[len] = '\0';
	    puts(buf);
	}
    } while (!err);

    gensio_free(lg);

    if (err != GE_REMCLOSE) {
	fprintf(stderr, "Error reading list data: %s\n",
		gensio_err_to_str(err));
	return 1;
    }

    return 0;
}

static void
term_handler(void *cb_data)
{
    struct gensio_waiter *waiter = cb_data;

    fflush(stdout);
    gensio_os_funcs_wake(o, waiter);
}

static const char *progname;

static void
help(int err)
{
    printf("%s [options] <device> [file]\n", progname);
    printf("\nA program to record/play sound using the sound gensio\n");
    printf("Data is read/written from/to stdin/stdout if a file isn't given.\n");
    printf("Sound goes to/from the given device.\n");
    printf("\noptions are:\n");
    printf("  -r, --rate <n> - The sample rate, defaults to 44100\n");
    printf("  -n, --nbufs <n> - The number of buffers, defaults to 100\n");
    printf("  -c, --channels <n> - The number of channels, defaults to 1\n");
    printf("  -s, --bufsize <n> - The buffer size, defaults to 2048\n");
    printf("  -t, --type <n> - The interface type, either alsa (Linux),\n"
	   "    win (Windows), or file.  Default to alsa or win.\n");
    printf("  -f, --format <str> - The I/O format.  Default to float.  May\n"
	   "    be one of double, float, int32, int24, int16, or int8\n");
    printf("  -p, --play - Playback data from stdin.  The default is to\n"
	   "    record data to stdout.\n");
    printf("  -L, --list-devs - List available devices and exit.\n");
    printf("  -d, --debug - Enable debug.  Specify more than once to increase\n"
	   "    the debug level\n");
    printf("  -h, --help - This help\n");
    gensio_osfunc_exit(err);
}

int
main(int argc, char *argv[])
{
    int rv, arg;
    struct gensio_os_proc_data *proc_data;
    unsigned int bufsize = 2048;
    unsigned int sample_rate = 44100;
    unsigned int num_bufs = 100;
    struct gensio *io;
    struct gensio_waiter *waiter;
    char *gensiostr;
    bool list_devs = false;
    bool play = false;
    const char *devtype = NULL; /* Take the default by default. */
    const char *format = "float";

    progname = argv[0];

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
	} else if ((rv = cmparg(argc, argv, &arg, "-h", "--help", NULL))) {
	    help(0);
	} else {
	    fprintf(stderr, "Unknown argument: %s, us -h for help\n",
		    argv[arg]);
	    return 1;
	}
    }

    rv = gensio_default_os_hnd(GENSIOSIG, &o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    gensio_os_funcs_set_vlog(o, do_vlog);

    rv = gensio_os_proc_setup(o, &proc_data);
    if (rv) {
	fprintf(stderr, "Could not setup process data: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    if (list_devs) {
	list_sound_devs(o, devtype);
	return 0;
    }

    if (arg >= argc) {
	fprintf(stderr, "No sound device given\n");
	return 1;
    }

    infile = stdin;
    outfile = stdout;

    if (arg + 1 < argc) {
	if (play) {
	    infile = fopen(argv[arg + 1], "rb");
	    if (!infile) {
		fprintf(stderr, "Unable to open %s\n", argv[arg + 1]);
		return 1;
	    }
	} else {
	    outfile = fopen(argv[arg + 1], "wb");
	    if (!outfile) {
		fprintf(stderr, "Unable to open %s\n", argv[arg + 1]);
		return 1;
	    }
	}
    }

    if (channels == 0) {
	fprintf(stderr, "channels must be >= 1\n");
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
