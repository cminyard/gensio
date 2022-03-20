//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

// This is an example telnet client in Go.  It reads line-at-a time.

package main

import (
	"fmt"
	"github.com/cminyard/go/gensio"
)

type closeDone struct {
	gensio.GensioCloseDoneBase
	ie *ioEvent
}

func (cd *closeDone) CloseDone() {
	cd.ie.info.w.Wake()
	cd.ie.g = nil
	cd.ie.otherie.g = nil
	cd.ie.otherie = nil
	cd.ie = nil
}

type ioInfo struct {
	w *gensio.Waiter
	errstr string
	inClose bool
}

type ioEvent struct {
	gensio.EventBase
	g gensio.Gensio
	otherie *ioEvent
	info *ioInfo
}

func (ie *ioEvent) startClose() {
	if ie.info.inClose {
		return
	}
	ie.info.inClose = true
	ie.g.SetReadCallbackEnable(false)
	ie.g.SetWriteCallbackEnable(false)
	ie.otherie.g.SetReadCallbackEnable(false)
	ie.otherie.g.SetWriteCallbackEnable(false)
	cdh := &closeDone{}
	cdh.ie = ie
	ie.g.Close(cdh)
	cdh = &closeDone{}
	cdh.ie = ie.otherie
	ie.otherie.g.Close(cdh)
}

func (ie *ioEvent) Read(err int, data []byte, auxdata []string) uint64 {
	if err != 0 {
		ie.info.errstr = gensio.ErrToStr(err)
		ie.startClose()
		return 0
	}

	defer func() {
		if r := recover(); r != nil {
			ie.info.errstr = fmt.Sprintf("%s", r)
			ie.startClose()
		}
	}()
	count := ie.g.Write(data, nil)

	if count < uint64(len(data)) {
		ie.g.SetReadCallbackEnable(false)
		ie.otherie.g.SetWriteCallbackEnable(true)
	}
	return count
}

func (ie *ioEvent) WriteReady() {
	ie.otherie.g.SetReadCallbackEnable(true)
	ie.g.SetWriteCallbackEnable(false)
}

type LogHandler struct {
	gensio.LoggerBase
}

func (l *LogHandler) Log(level int, log string) {
	fmt.Printf("LOG(%s): %s\n", gensio.LogLevelToStr(level), log)
}

func main() {
	o := gensio.NewOsFuncs(&LogHandler{})
	w := gensio.NewWaiter(o)
	info := ioInfo{w, "", false}

	telnetEvent := &ioEvent{}
	telnetEvent.info = &info;

	userEvent := &ioEvent{}
	userEvent.info = &info;

	userEvent.g = gensio.NewGensio("stdio(self)", o, userEvent)
	userEvent.g.OpenS()

	telnetEvent.g = gensio.NewGensio("telnet,tcp,localhost,1234", o,
		telnetEvent)
	telnetEvent.g.OpenS()

	userEvent.otherie = telnetEvent
	telnetEvent.otherie = userEvent

	userEvent.g.SetReadCallbackEnable(true)
	telnetEvent.g.SetReadCallbackEnable(true)

	w.Wait(2, nil)

	fmt.Println("Shut down due to:", info.errstr);
}
