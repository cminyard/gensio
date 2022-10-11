/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2022  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This accounts for dumb things Windows does with security.  It's a
 * helper process for when starting a process as another user.
 *
 * See comments in gensio_osops.c above start_pty_helper for details.
 */
#include <stdio.h>
#include <windows.h>

struct pty_helper_cmd {
    unsigned int cmd;
    unsigned int size;
    union {
	struct {
	    int x;
	    int y;
	} resize;
    };
};
#define PTY_RESIZE 1

static HANDLE ctl_s = NULL;
static HANDLE readh_m = NULL;
static HANDLE writeh_m = NULL;
static HANDLE in = NULL;
static HANDLE out = NULL;
static HPCON ptyh = NULL;
static HANDLE done_ev = NULL;
static volatile BOOL in_exit = FALSE;

static void
run_cmd(struct pty_helper_cmd *cmd)
{
    COORD size;

    switch (cmd->cmd) {
    case PTY_RESIZE:
	size.Y = cmd->resize.y;
	size.X = cmd->resize.x;
	ResizePseudoConsole(ptyh, size);
	break;
    default:
	break;
    }
}

static DWORD WINAPI
cmd_handler(LPVOID data)
{
    struct pty_helper_cmd cmd;
    unsigned char *buf = (unsigned char *) &cmd;
    DWORD buflen = 0, len;

    while (!in_exit) {
	if (!ReadFile(ctl_s, buf + buflen, sizeof(cmd) - buflen, &len,
		      NULL))
	    break;
	buflen += len;
	if (buflen >= sizeof(cmd)) {
	    buflen = 0;
	    run_cmd(&cmd);
	}
    }
    SetEvent(done_ev);

    return 0;
}

static DWORD WINAPI
to_child_handler(LPVOID data)
{
    unsigned char buf[1024];
    DWORD buflen, len;

    while (!in_exit) {
	if (!ReadFile(in, buf, sizeof(buf), &buflen, NULL))
	    break;
	if (!WriteFile(writeh_m, buf, buflen, &len, FALSE))
	    break;
    }
    SetEvent(done_ev);
    return 0;
}

static DWORD WINAPI
from_child_handler(LPVOID data)
{
    unsigned char buf[1024];
    DWORD buflen, len;

    while (!in_exit) {
	if (!ReadFile(readh_m, buf, sizeof(buf), &buflen, NULL))
	    break;
	if (!WriteFile(out, buf, buflen, &len, FALSE))
	    break;
    }
    SetEvent(done_ev);
    return 0;
}

int main(int argc, char *argv[])
{
    HANDLE shmem;
    char *buf, *cmdline;
    HANDLE readh_s = NULL, writeh_s = NULL;
    HANDLE thread1 = NULL, thread2 = NULL, thread3 = NULL;
    HANDLE h[2];
    COORD winsize;
    HRESULT hr;
    STARTUPINFOEX si;
    PROCESS_INFORMATION procinfo;
    size_t len;
    DWORD exit_code = 0;

    if (argc < 4)
	return 1;

    in = GetStdHandle(STD_INPUT_HANDLE);
    out = GetStdHandle(STD_OUTPUT_HANDLE);

    shmem = (HANDLE) strtoll(argv[1], NULL, 0);
    buf = (char *) MapViewOfFile(shmem,
				 FILE_MAP_ALL_ACCESS,
				 0,
				 0,
				 strtoul(argv[2], NULL, 0));
    if (!buf)
	return 1;
    ctl_s = (HANDLE) strtoll(argv[3], NULL, 0);

    if (buf[0] != 1) /* Version */
	return 1;

    cmdline = buf + 1;

    done_ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!done_ev)
	return 1;

    if (!CreatePipe(&writeh_s, &writeh_m, NULL, 0))
	return 1;
    if (!SetHandleInformation(writeh_s, HANDLE_FLAG_INHERIT,
			      HANDLE_FLAG_INHERIT))
	return 1;
    if (!CreatePipe(&readh_m, &readh_s, NULL, 0))
	return 1;
    if (!SetHandleInformation(readh_s, HANDLE_FLAG_INHERIT,
			      HANDLE_FLAG_INHERIT))
	return 1;

    winsize.X = 80;
    winsize.Y = 25;
    hr = CreatePseudoConsole(winsize, writeh_s, readh_s, 0, &ptyh);
    if (hr != S_OK)
	return 1;

    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);
    si.StartupInfo.hStdInput = writeh_s;
    si.StartupInfo.hStdOutput = readh_s;
    si.StartupInfo.hStdError = readh_s;
    si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;

    InitializeProcThreadAttributeList(NULL, 1, 0, &len);
    si.lpAttributeList = calloc(1, len);
    if (!si.lpAttributeList)
	return 1;
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &len))
	return 1;
    if (!UpdateProcThreadAttribute(si.lpAttributeList,
				   0,
				   PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
				   ptyh,
				   sizeof(ptyh),
				   NULL,
				   NULL))
	return 1;

    if (!CreateProcess(NULL,
		       cmdline,
		       NULL,
		       NULL,
		       FALSE,
		       (NORMAL_PRIORITY_CLASS |
			EXTENDED_STARTUPINFO_PRESENT),
		       NULL,
		       NULL,
		       &si.StartupInfo,
		       &procinfo))
	return 1;

    DeleteProcThreadAttributeList(si.lpAttributeList);
    free(si.lpAttributeList);

    CloseHandle(writeh_s);
    CloseHandle(readh_s);

    thread1 = CreateThread(NULL, 0, cmd_handler, NULL, 0, NULL);
    if (!thread1)
	return 1;
    thread2 = CreateThread(NULL, 0, to_child_handler, NULL, 0, NULL);
    if (!thread2)
	return 1;
    thread3 = CreateThread(NULL, 0, from_child_handler, NULL, 0, NULL);
    if (!thread3)
	return 1;

    h[0] = done_ev;
    h[1] = procinfo.hProcess;
    WaitForMultipleObjects(2, h, FALSE, INFINITE);

    in_exit = TRUE;

    CancelSynchronousIo(thread1);
    while (WaitForSingleObject(thread1, 1) == WAIT_TIMEOUT)
	CancelSynchronousIo(thread1);
    CloseHandle(thread1);

    CancelSynchronousIo(thread2);
    while (WaitForSingleObject(thread2, 1) == WAIT_TIMEOUT)
	CancelSynchronousIo(thread2);
    CloseHandle(thread2);

    CancelSynchronousIo(thread3);
    while (WaitForSingleObject(thread3, 1) == WAIT_TIMEOUT)
	CancelSynchronousIo(thread3);
    CloseHandle(thread3);

    CloseHandle(readh_m);
    CloseHandle(writeh_m);
    CloseHandle(in);
    CloseHandle(out);
    CloseHandle(ctl_s);

    CloseHandle(done_ev);

    WaitForSingleObject(procinfo.hProcess, INFINITE);
    GetExitCodeProcess(procinfo.hProcess, &exit_code);
    CloseHandle(procinfo.hProcess);

    ClosePseudoConsole(ptyh);

    return exit_code;
}
