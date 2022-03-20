//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

// This is an example telnet server in Go

package main

import (
	"fmt"
	"github.com/cminyard/go/gensio"
)

type closeDone struct {
	gensio.GensioCloseDoneBase
	g gensio.Gensio
	w *gensio.Waiter
	se *serverEvent
}

func (cd *closeDone) CloseDone() {
	cd.w.Wake()
	cd.g = nil
	cd.w = nil
	cd.se.g = nil
	cd.se = nil
}

type serverEvent struct {
	gensio.EventBase
	g gensio.Gensio
	w *gensio.Waiter
	errstr *string
}

func (se *serverEvent) startClose() {
	se.g.SetReadCallbackEnable(false)
	se.g.SetWriteCallbackEnable(false)
	cdh := &closeDone{}
	cdh.g = se.g
	cdh.w = se.w
	cdh.se = se
	se.g.Close(cdh)
}

func (se *serverEvent) Read(err int, data []byte, auxdata []string) uint64 {
	if err != 0 {
		*se.errstr = gensio.ErrToStr(err)
		se.startClose()
		return 0
	}

	defer func() {
		if r := recover(); r != nil {
			*se.errstr = fmt.Sprintf("%s", r)
			se.startClose()
		}
	}()
	count := se.g.Write(data, nil)

	if count < uint64(len(data)) {
		se.g.SetReadCallbackEnable(false)
		se.g.SetWriteCallbackEnable(true)
	}
	return count
}

func (se *serverEvent) WriteReady() {
	se.g.SetReadCallbackEnable(true)
	se.g.SetWriteCallbackEnable(false)
}

type accepterShutdownDone struct {
	gensio.AccepterShutdownDoneBase
	w *gensio.Waiter
	ae *accepterEvent
}

func (asd *accepterShutdownDone) AccShutdownDone() {
	asd.ae.acc = nil
	asd.ae = nil
	asd.w.Wake()
}

type accepterEvent struct {
	gensio.AccepterEventBase
	acc gensio.Accepter
	w *gensio.Waiter
	errstr *string
}

func (ae *accepterEvent) Log(level int, log string) {
	fmt.Printf("LOG(%s): %s\n", gensio.LogLevelToStr(level), log)
}

func (ae *accepterEvent) NewConnection(g gensio.Gensio) {
	se := &serverEvent{}
	se.g = g
	se.w = ae.w
	se.errstr = ae.errstr
	g.SetEvent(se)
	g.SetReadCallbackEnable(true)
	asd := &accepterShutdownDone{}
	asd.w = ae.w
	asd.ae = ae
	ae.acc.Shutdown(asd)
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
	errstr := ""
	ae := &accepterEvent{}
	ae.w = w
	ae.errstr = &errstr
	ae.acc = gensio.NewAccepter("telnet,tcp,1234", o, ae)
	ae.acc.Startup()

	w.Wait(2, nil)

	fmt.Println("Shut down due to:", errstr);
}
