/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 * This program tests if openssl screws up the signal masks for all
 * threads by calling sicprocmask.  This may only run under macos, it
 * may need fixes for other platforms.  Run it with:
 *
 *   DYLD_LIBRARY_PATH=/opt/homebrew/lib ./ssl_thread_issue
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <assert.h>
#include <sys/select.h>

struct cross_thread_info {
    int waitfd;
    int err;
};

static void *
cross_thread(void *data)
{
    struct cross_thread_info *info = data;
    sigset_t sigmask, omask;
    int rv = 0;
    fd_set rfds;

    rv = pthread_sigmask(SIG_SETMASK, NULL, &sigmask);
    assert(rv == 0);

    if (!sigismember(&sigmask, SIGUSR1)) {
	fprintf(stderr, "SIGUSR1 not in sigmask 1\n");
	info->err = 1;
	goto out_err;
    }

    FD_ZERO(&rfds);
    FD_SET(info->waitfd, &rfds);
    sigdelset(&sigmask, SIGUSR1);
    rv = pthread_sigmask(SIG_SETMASK, &sigmask, &omask);
    assert(rv == 0);

    rv = pselect(info->waitfd + 1, &rfds, NULL, NULL, NULL, NULL);
    assert(rv == 1);

    rv = pthread_sigmask(SIG_SETMASK, &omask, &sigmask);
    assert(rv == 0);
    if (sigismember(&sigmask, SIGUSR1)) {
	fprintf(stderr, "SIGUSR1 in sigmask 1\n");
	info->err = 4;
	goto out_err;
    }

 out_err:
    return NULL;
}

static int
check_pselect_cross_thread(sigset_t mask)
{
    int rv = 1;
    int pipefds[2] = { -1, -1 };
    struct cross_thread_info info;
    pthread_t th;
    char dummy = 0;

    rv = pipe(pipefds);
    if (rv == -1) {
	perror("pipe");
	return 1;
    }

    info.err = 0;
    info.waitfd = pipefds[0];
    rv = pthread_create(&th, NULL, cross_thread, &info);

    sleep(2); /* Give the thread time to enter pselect() */

    if (dlopen("libssl.dylib", RTLD_LAZY | RTLD_GLOBAL) == NULL) {
	fprintf(stderr, "dlopen failed: %s\n", dlerror());
	rv = 1;
    }

    write(pipefds[1], &dummy, 1);

    pthread_join(th, NULL);

    if (!rv)
	rv = info.err;

    if (!rv)
	printf("dlopen does not affect other threads' sigmasks\n");

    close(pipefds[0]);
    close(pipefds[1]);
    return rv;
}

int
main(int argc, char *argv[])
{
    sigset_t mask;
    int rv;

    /* Start with SIGUSR1 blocked. */
    rv = sigprocmask(SIG_SETMASK, NULL, &mask);
    assert(rv == 0);
    sigaddset(&mask, SIGUSR1);
    rv = sigprocmask(SIG_SETMASK, &mask, NULL);
    assert(rv == 0);

    rv = check_pselect_cross_thread(mask);
    return rv;
}
