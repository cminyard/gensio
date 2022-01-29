//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

package main

import (
	"fmt"
	"github.com/cminyard/go/gensio"
	"testbase"
)

type TelnetReflEvHnd struct {
	testbase.ReflEvHnd
	gotBreak bool
	w *gensio.Waiter
}

func (treh *TelnetReflEvHnd) SendBreak() {
	treh.gotBreak = true
	treh.w.Wake()
}

type OpenDone struct {
	gensio.GensioOpenDoneBase
	err int
	w *gensio.Waiter
}

func (oh *OpenDone) OpenDone(err int) {
	oh.err = err
	oh.w.Wake()
}

type CloseDone struct {
	gensio.GensioCloseDoneBase
	w *gensio.Waiter
}

func (oh *CloseDone) CloseDone() {
	oh.w.Wake()
}

func testSync(o *gensio.OsFuncs) {
	fmt.Println("Test sync I/O")
	r := testbase.NewReflector(o, "tcp,0", nil)
	r.Startup()
	port := r.GetPort()

	g := gensio.NewGensio("tcp,localhost," + port, o, nil)
	g.OpenS()
	g.SetSync()
	outstr := []byte("Test sync string")
	rv, count := g.WriteS(outstr, gensio.NewTime(1, 0), false)
	if rv != 0 {
		panic("WriteS returned error: " + gensio.ErrToStr(rv))
	}
	if count != uint64(len(outstr)) {
		panic("WriteS returned too few bytes: ")
	}
	data := make([]byte, 100)
	rv, newdata := g.ReadS(data, gensio.NewTime(1, 0), false)
	if rv != 0 {
		panic("ReadS returned error: " + gensio.ErrToStr(rv))
	}
	if ! testbase.Cmpbytes(newdata, outstr) {
		panic("Data mismatch")
	}
	g.CloseS()
	r.CloseS()
	r.ShutdownS()
}

func testAsync(o *gensio.OsFuncs) {
	fmt.Println("Test async I/O")
	treh := &TelnetReflEvHnd{}
	r := testbase.NewReflector(o, "telnet,tcp,0", treh)
	r.Startup()
	port := r.GetPort()
	r.SetEnableCb(false)
	rv := r.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for cb disable: " + gensio.ErrToStr(rv))
	}
	r.SetEnableS(false)
	r.SetEnable(true)

	h := &testbase.EvHnd{}
	h.Setup(o)
	g := gensio.NewGensio("telnet,tcp,localhost," + port, o, h)
	h.SetGensio(g)
	oh := &OpenDone{}
	oh.w = gensio.NewWaiter(o)
	g.Open(oh)
	rv = oh.w.Wait(uint(1), gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for open: " + gensio.ErrToStr(rv))
	}
	if oh.err != 0 {
		panic("Error from open: " + gensio.ErrToStr(oh.err))
	}
	oh = nil

	teststr := []byte("Test string")
	h.SetData(teststr)
	rv = h.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for data: " + gensio.ErrToStr(rv))
	}

	ch := &CloseDone{}
	ch.w = gensio.NewWaiter(o)
	g.Close(ch)
	rv = ch.w.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for close: " + gensio.ErrToStr(rv))
	}
	ch = nil
	r.CloseS()

	r.Shutdown()
	rv = r.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for shutdown: " + gensio.ErrToStr(rv))
	}
}

func main() {
	fmt.Println("Starting basic Go tests")

	o := testbase.O
	gensio.SetLogMask(gensio.LOG_MASK_ALL)
	o.Log(gensio.LOG_INFO, "Test Log")

	testSync(o)
	testAsync(o)

	o = nil

	testbase.TestShutdown()
}
