/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2022  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

struct file_info {
    FILE *f;
    bool finished;
    bool is_stdio;
};

static void
gensio_sound_file_api_close_dev(struct sound_info *si)
{
    struct file_info *a = si->pinfo;

    if (a && a->f) {
	if (!a->is_stdio)
	    fclose(a->f);
	a->f = NULL;
    }
}

static void
gensio_sound_file_api_next_read(struct sound_info *si)
{
    struct file_info *a = si->pinfo;
    size_t rv;

    if (si->len > 0)
	return;

    if (si->cnv.enabled)
	rv = fread(si->cnv.buf, si->cnv.pframesize, si->bufsize, a->f);
    else
	rv = fread(si->buf, si->framesize, si->bufsize, a->f);
    if (rv != si->bufsize) {
	si->soundll->err = GE_REMCLOSE;
	return;
    }

    if (si->cnv.enabled) {
	const unsigned char *ibuf = si->cnv.buf;
	unsigned char *obuf = si->buf;
	gensiods i;

	for (i = 0; i < si->bufsize * si->chans; i++)
	    si->cnv.convin(&ibuf, &obuf, &si->cnv);
    }
    si->len = si->bufsize;
    si->ready = true;
}

static void
gensio_sound_file_api_set_read(struct sound_info *si, bool enable)
{
    if (enable)
	gensio_sound_file_api_next_read(si);
}

static void
gensio_sound_file_api_set_write(struct sound_info *si, bool enable)
{
}

static unsigned int
gensio_sound_file_api_start_close(struct sound_info *si)
{
    struct file_info *a = si->pinfo;

    if (a->f) {
	if (!a->is_stdio)
	    fclose(a->f);
	a->f = NULL;
    }
    return 0;
}

static int
gensio_sound_file_api_write(struct sound_info *out, const unsigned char *buf,
			    gensiods buflen, gensiods *nr_written)
{
    struct file_info *a = out->pinfo;
    size_t rv;
    int err = 0;

    if (out->cnv.enabled)
	rv = fwrite(buf, out->cnv.pframesize, buflen, a->f);
    else
	rv = fwrite(buf, out->framesize, buflen, a->f);
    if (rv != buflen)
	err = GE_IOERR;
    else
	*nr_written = buflen;
    return err;
}

static int
gensio_sound_file_api_open_dev(struct sound_info *si)
{
    struct file_info *a = si->pinfo;
    struct gensio_os_funcs *o = si->soundll->o;

    if (strcmp(si->devname, "-") == 0) {
	a->is_stdio = true;
	if (si->is_input)
	    a->f = stdin;
	else
	    a->f = stdout;
    } else {
	a->is_stdio = false;
	a->f = fopen(si->devname, si->is_input ? "r" : "w");
	if (!a->f)
	    return GE_NOTFOUND;
    }

    if (si->cnv.enabled) {
	si->cnv.pframesize = (gensiods) si->cnv.psize * si->chans;
	si->cnv.buf = o->zalloc(o, si->bufsize * si->cnv.pframesize);
	if (!si->cnv.buf) {
	    if (!a->is_stdio)
		fclose(a->f);
	    a->f = NULL;
	    return GE_NOMEM;
	}
    }

    if (!si->is_input)
	si->ready = true; /* Write is always ready. */
    
    return 0;
}

int
gensio_sound_file_api_devices(char ***rnames, char ***rspecs, gensiods *rcount)
{
    *rnames = NULL;
    *rspecs = NULL;
    *rcount = 0;
    return 0;
}

static int
gensio_sound_file_api_setup(struct sound_info *si, struct gensio_sound_info *io)
{
    struct gensio_os_funcs *o = si->soundll->o;

    si->pinfo = o->zalloc(o, sizeof(struct file_info));
    if (!si->pinfo)
	return GE_NOMEM;

    return 0;
}

static void
gensio_sound_file_api_cleanup(struct sound_info *si)
{
    struct gensio_os_funcs *o = si->soundll->o;

    if (si->pinfo)
	o->free(o, si->pinfo);
}

static struct sound_type file_sound_type = {
    "file",
    .setup = gensio_sound_file_api_setup,
    .cleanup = gensio_sound_file_api_cleanup,
    .open_dev = gensio_sound_file_api_open_dev,
    .close_dev = gensio_sound_file_api_close_dev,
    .sub_write = gensio_sound_file_api_write,
    .write = gensio_sound_api_default_write,
    .set_write_enable = gensio_sound_file_api_set_write,
    .set_read_enable = gensio_sound_file_api_set_read,
    .next_read = gensio_sound_file_api_next_read,
    .start_close = gensio_sound_file_api_start_close,
    .devices = gensio_sound_file_api_devices
};

#define FILE_INIT &file_sound_type,
