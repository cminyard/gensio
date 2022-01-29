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

	testbase.ObjCount++
	r := testbase.NewReflector(o, "tcp,0", nil)
	r.Startup()
	port := r.GetPort()

	testbase.ObjCount++
	t := gensio.NewTime(0, 0)

	testbase.ObjCount++
	g := gensio.NewGensio("tcp,localhost," + port, o, nil)

	g.OpenS()
	g.SetSync()
	outstr := []byte("Test sync string")
	t.SetTime(1, 0)
	rv, count := g.WriteS(outstr, t, false)
	if rv != 0 {
		panic("WriteS returned error: " + gensio.ErrToStr(rv))
	}
	if count != uint64(len(outstr)) {
		panic("WriteS returned too few bytes: ")
	}
	data := make([]byte, 100)
	t.SetTime(1, 0)
	rv, newdata := g.ReadS(data, t, false)
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

	testbase.ObjCount++
	t := gensio.NewTime(0, 0)

	testbase.ObjCount++
	treh := &TelnetReflEvHnd{}

	testbase.ObjCount++
	r := testbase.NewReflector(o, "telnet,tcp,0", treh)
	r.Startup()
	port := r.GetPort()

	r.SetEnableCb(false)
	t.SetTime(1, 0)
	rv := r.Wait(1, t)
	if rv != 0 {
		panic("Error waiting for cb disable: " + gensio.ErrToStr(rv))
	}
	r.SetEnableS(false)
	r.SetEnable(true)

	testbase.ObjCount++
	h := &testbase.EvHnd{}

	h.Setup(o)
	testbase.ObjCount++
	g := gensio.NewGensio("telnet,tcp,localhost," + port, o, h)
	h.SetGensio(g)
	testbase.ObjCount++

	st := g.GetType(0)
	if st != "telnet" {
		panic(fmt.Sprintf("Wrong gensio type, expected telnet, got %s\n", st))
	}
	st = g.GetType(1)
	if st != "tcp" {
		panic(fmt.Sprintf("Wrong gensio type, expected tcp, got %s\n", st))
	}
	st = g.GetType(2)
	if len(st) != 0 {
		panic("Got a gensio type when exceeding depth")
	}

	oh := &OpenDone{}
	testbase.ObjCount++
	oh.w = gensio.NewWaiter(o)
	g.Open(oh)
	t.SetTime(1, 0)
	rv = oh.w.Wait(1, t)
	if rv != 0 {
		panic("Error waiting for open: " + gensio.ErrToStr(rv))
	}
	if oh.err != 0 {
		panic("Error from open: " + gensio.ErrToStr(oh.err))
	}
	oh = nil

	teststr := []byte("Test string")
	h.SetData(teststr)
	t.SetTime(1, 0)
	rv = h.Wait(1, t)
	if rv != 0 {
		panic("Error waiting for data: " + gensio.ErrToStr(rv))
	}

	testbase.ObjCount++
	ch := &CloseDone{}
	testbase.ObjCount++
	ch.w = gensio.NewWaiter(o)
	g.Close(ch)
	t.SetTime(1, 0)
	rv = ch.w.Wait(1, t)
	if rv != 0 {
		panic("Error waiting for close: " + gensio.ErrToStr(rv))
	}
	ch = nil
	r.CloseS()

	r.Shutdown()
	t.SetTime(1, 0)
	rv = r.Wait(1, t)
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

	gensio.Debug = true
	testbase.TestShutdown()
	fmt.Println("Pass")
}
