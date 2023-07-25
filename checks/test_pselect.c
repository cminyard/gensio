/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 * This program tests the following:
 *
 * * Is pselect() atomic?  In other words, does it apply the signal
 *   mask and wait for the FDs at the same time.  If it applies the
 *   signal mask then waits for the FDs, there is a window where a
 *   signal can happen and not wake up the pselect(), so a workaround
 *   is needed.
 *
 * * Does sigprocmask() affect all threads, or just the calling
 *   thread?  There is no need right now for a workaround on this, but
 *   it might be useful debugging information.
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <sys/select.h>

volatile int signalled;

static void
sigusr1_handler(int sig)
{
    signalled = 1;
}

static int
check_pselect_atomic(sigset_t mask)
{
    fd_set rfds;
    int rv = 1;
    struct timespec to;
    int pipefds[2] = { -1, -1 };

    signalled = 0;
    rv = pipe(pipefds);
    if (rv == -1) {
	perror("pipe");
	return 1;
    }

    rv = kill(0, SIGUSR1);
    if (rv == -1) {
	perror("kill");
	goto out;
    }

    if (signalled) {
	fprintf(stderr, "Signal called on blocked signal\n");
	rv = 2;
	goto out;
    }

    FD_ZERO(&rfds);
    FD_SET(pipefds[0], &rfds);

    to.tv_sec = 2;
    to.tv_nsec = 0;
    sigdelset(&mask, SIGUSR1);
    rv = pselect(pipefds[0] + 1, &rfds, NULL, NULL, &to, &mask);
    if (rv == 0) {
	fprintf(stderr, "Timeout, pselect signal handling is not atomic\n");
	rv = 2;
	goto out;
    } else if (rv == -1) {
	if (errno != EINTR) {
	    fprintf(stderr, "Unknown pselect error: %s\n", strerror(errno));
	    rv = 1;
	    goto out;
	}
    } else {
	fprintf(stderr, "Unknown pselect return: %d\n", rv);
	rv = 1;
	goto out;
    }
    if (!signalled) {
	fprintf(stderr, "Signal didn't happen\n");
	rv = 2;
	goto out;
    }
    rv = 0;

    printf("pselect is atomic\n");
 out:
    close(pipefds[0]);
    close(pipefds[1]);
    return rv;
}

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
    if (rv) {
	perror("pthread_sigmask 3");
	info->err = 1;
	goto out_err;
    }

    if (!sigismember(&sigmask, SIGUSR1)) {
	fprintf(stderr, "SIGUSR1 not in sigmask 1\n");
	info->err = 1;
	goto out_err;
    }

    FD_ZERO(&rfds);
    FD_SET(info->waitfd, &rfds);
    sigdelset(&sigmask, SIGUSR1);
    rv = pthread_sigmask(SIG_SETMASK, &sigmask, &omask);
    if (rv) {
	perror("pthread_sigmask 4");
	info->err = 1;
	goto out_err;
    }

    rv = pselect(info->waitfd + 1, &rfds, NULL, NULL, NULL, NULL);

    rv = pthread_sigmask(SIG_SETMASK, &omask, &sigmask);
    if (rv) {
	perror("pthread_sigmask 3");
	info->err = 1;
	goto out_err;
    }
    if (sigismember(&sigmask, SIGUSR1)) {
	fprintf(stderr, "SIGUSR1 in sigmask 1, sigprocmask affects all threads\n");
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

    signalled = 0;
    rv = pipe(pipefds);
    if (rv == -1) {
	perror("pipe");
	return 1;
    }

    info.err = 0;
    info.waitfd = pipefds[0];
    rv = pthread_create(&th, NULL, cross_thread, &info);

    sleep(2); /* Give the thread time to enter pselect() */

    sigaddset(&mask, SIGUSR1);
    rv = sigprocmask(SIG_SETMASK, &mask, NULL);
    if (rv == -1) {
	perror("sigprocmask 4");
	rv = 1;
	goto out;
    }

    write(pipefds[1], &dummy, 1);

    pthread_join(th, NULL);

    if (!rv)
	rv = info.err;

    if (!rv)
	printf("sigprocmask does not affect other threads\n");
 out:
    close(pipefds[0]);
    close(pipefds[1]);
    return rv;
}

int
main(int argc, char *argv[])
{
    sigset_t mask;
    struct sigaction action;
    int rv;

    /* Start with SIGUSR1 blocked and with a handler. */
    rv = sigprocmask(SIG_SETMASK, NULL, &mask);
    if (rv == -1) {
	perror("sigprocmask 1");
	return 1;
    }
    sigaddset(&mask, SIGUSR1);
    rv = sigprocmask(SIG_SETMASK, &mask, NULL);
    if (rv == -1) {
	perror("sigprocmask 2");
	return 1;
    }

    action.sa_flags = 0;
    action.sa_mask = mask;
    action.sa_handler = sigusr1_handler;
    rv = sigaction(SIGUSR1, &action, NULL);
    if (rv == -1) {
	perror("sigaction");
	return 1;
    }

    rv = check_pselect_atomic(mask);
    rv |= check_pselect_cross_thread(mask);
    return rv;
}
