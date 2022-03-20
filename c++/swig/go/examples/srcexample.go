//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

package main

import (
	"fmt"
	"runtime"
	"github.com/cminyard/go/gensio"
)

type AccGEvHnd struct {
	gensio.EventBase
	g gensio.Gensio
}

func (e *AccGEvHnd) Read(err int, data []byte, auxdata []string) uint64 {
	fmt.Printf("acc read: %s\n", string(data))
	fmt.Printf("aux: %v\n", auxdata)
	e.g.Write(data, nil)
	return uint64(len(data))
}

func (e *AccGEvHnd) WriteReady() {
	fmt.Println("acc write ready")
	e.g.SetWriteCallbackEnable(false)
}

type AccEvHnd struct {
	gensio.AccepterEventBase
}

func (ae *AccEvHnd) NewConnection(g gensio.Gensio) {
	fmt.Println("Acc New connection")
	gev := &AccGEvHnd{}
	gev.g = g
	g.SetEvent(gev)
	g.SetReadCallbackEnable(true)
}

type EvHnd struct {
	gensio.SerialEventBase

	g gensio.Gensio
	writedata []byte
	readdata []byte
	w *gensio.Waiter
}

func (e *EvHnd) IsEvHndGo() { }

func (e *EvHnd) destroy() {
	//gensio.DeleteWaiter(e.w)
	//gensio.DeleteDirectorEvent(e.Event)
}

func (e *EvHnd) Read(err int, data []byte, auxdata []string) uint64 {
	e.g.SetReadCallbackEnable(false)
	e.readdata = data
	fmt.Printf("read: %s\n", string(data))
	fmt.Printf("aux: %v\n", auxdata)
	e.w.Wake()
	return uint64(len(data))
}

func (e *EvHnd) WriteReady() {
	fmt.Println("write ready")
	e.g.SetWriteCallbackEnable(false)
	e.g.Write(e.writedata, nil)
	e.g.SetReadCallbackEnable(true)
}

func (e *EvHnd) Freed() {
	fmt.Println("freed two")
}

func (e *EvHnd) wait(count uint, timeout *gensio.Time) {
	e.w.Wait(count, timeout)
}

func (e *EvHnd) set_write_data(data []byte) {
	e.writedata = data
}

func NewEvHnd(o *gensio.OsFuncs) *EvHnd {
	e := &EvHnd{}
	e.w = gensio.NewWaiter(o)
	return e
}

type EvHndDelI interface {
	destroy()
}

type asdf struct{
	x int64
}

func (e *asdf) destroy() {
	fmt.Println("asdf destroy")
}

func check() int64 {
	a := &asdf{10}
	return a.x
}

type Open_Done struct {
	gensio.GensioOpenDoneBase
	w *gensio.Waiter
	err int
}

func NewOpen_Done(o *gensio.OsFuncs) *Open_Done {
	od := &Open_Done{}
	od.w = gensio.NewWaiter(o)
	od.err = gensio.GE_TIMEDOUT
	return od
}
func (od *Open_Done) wait(count uint, timeout *gensio.Time) {
	od.w.Wait(count, timeout)
}
func (od *Open_Done) OpenDone(err int) {
	od.err = err
	od.w.Wake()
}

type LogHandler struct {
	gensio.LoggerBase
}

func (l *LogHandler) Log(level int, log string) {
	fmt.Printf("LOG(%s): %s\n", gensio.LogLevelToStr(level), log)
}

func main() {
	o := gensio.NewOsFuncs(&LogHandler{})
	gensio.SetLogMask(gensio.LOG_MASK_ALL)
	o.Log(gensio.LOG_INFO, "Test Log")

	acch := &AccEvHnd{}
	acc := gensio.NewAccepter("tcp,localhost,0", o, acch)
	acc.Startup()
	port := acc.GetPort()
	fmt.Printf("Accepter port: %s\n", port)

	e := NewEvHnd(o)
	g := gensio.NewGensio("tcp,localhost," + port, o, e)
	e.g = g
	e.set_write_data([]byte("Test1"))

	od := NewOpen_Done(o)
	g.Open(od)
	od.wait(1, gensio.NewTime(1, 0))
	if od.err != 0 {
		fmt.Printf("Error opening gensio: %d\n", od.err)
		return
	}
	od = nil

	var rv int
	var newdata []byte
	data := make([]byte, 0, 100)
	data = append(data, "0"...)
	rv, newdata, _ = g.Control(0, true, gensio.GENSIO_CONTROL_LADDR, data)
	fmt.Printf("laddr(%d): %s\n", rv, newdata)
	rv, newdata, _ = g.Control(0, true, gensio.GENSIO_CONTROL_RADDR, data)
	fmt.Printf("raddr(%d): %s\n", rv, newdata)

	fmt.Println("Testing sync I/O")
	g.SetSync()
	count := uint64(0)
	rv, count = g.WriteS([]byte("Sync I/O"), nil, false)
	fmt.Printf("Sync Write(%d): %d\n", rv, count)
	rv, newdata = g.ReadS(data, gensio.NewTime(1, 0), false)
	fmt.Printf("Sync Read(%d): %s\n", rv, newdata)
	g.ClearSync()

	g.SetWriteCallbackEnable(true)
	t := gensio.NewTime(check(), 0)
	e.wait(1, t)
	fmt.Printf("Done (%d %d): %s\n", t.GetSecs(), t.GetNsecs(),
		   string(e.readdata))
	g.CloseS()
	e.g = nil // Break the circular link
	e = nil
	g = nil
	t = nil
	acch = nil
	acc.ShutdownS()
	acc = nil

	e = NewEvHnd(o)
	g = gensio.NewGensio("serialdev,/dev/ttyEcho0,115200n81", o, e)
	g = nil

	runtime.GC()
	w := gensio.NewWaiter(o)
	w.Wait(uint(1), gensio.NewTime(1, 0))
	runtime.GC()
	w.Wait(uint(1), gensio.NewTime(1, 0))
	runtime.GC()
	w.Wait(uint(1), gensio.NewTime(1, 0))
}
