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

type AuxdataEvHnd struct {
	testbase.EvHnd
	wrauxdata []string
	rdauxdata []string
}

func (adev *AuxdataEvHnd) SetWrAuxdata(auxdata []string) {
	adev.wrauxdata = auxdata
}

func (adev *AuxdataEvHnd) SetRdAuxdata(auxdata []string) {
	adev.rdauxdata = auxdata
}

func (eh *AuxdataEvHnd) Read(err int, data []byte, auxdata []string) uint64 {
	if err == 0 {
		if len(auxdata) != len(eh.rdauxdata) {
			panic(fmt.Sprintf("auxdata length mismatch, expected %s, got %s",
				len(eh.rdauxdata), len(auxdata)))
		}
		for i, v := range auxdata {
			if v != eh.rdauxdata[i] {
				panic(fmt.Sprintf("auxdata parameter mismatch on %d, expected %s, got %s",
					i, eh.rdauxdata[i], v))
			}
		}
	}
	return eh.EvHnd.Read(err, data, auxdata)
}

func (eh *AuxdataEvHnd) WriteReady() {
	if eh.Data == nil || eh.Writepos >= len(eh.Data) {
		eh.G.SetWriteCallbackEnable(false)
		return
	}
	count := eh.G.Write(eh.Data[eh.Writepos:], eh.wrauxdata)
	eh.Writepos += int(count)
	if eh.Writepos >= len(eh.Data) {
		eh.G.SetWriteCallbackEnable(false)
	}
}

func main() {
	fmt.Println("Starting AX25 Go tests")

	o := testbase.O
	gensio.SetLogMask(gensio.LOG_MASK_ALL)

	testbase.ObjCount++
	r := testbase.NewReflector(o, "tcp,0", nil)
	r.Startup()
	port := r.GetPort()

	testbase.ObjCount++
	h := &AuxdataEvHnd{}
	h.Setup(o)
	testbase.ObjCount++
	g := gensio.NewGensio("ax25(laddr=AE5KM-1),kiss(server=yes),tcp,localhost," + port,
		o, h)
	h.SetGensio(g)
	rv, _, _ := g.Control(0, false, gensio.GENSIO_CONTROL_ENABLE_OOB,
		[]byte("1"))
	if rv != 0 {
		panic("Error enabling oob: " + gensio.ErrToStr(rv))
	}

	g.OpenS()

	h.SetWrAuxdata([]string{"pid:33", "addr:0,AE5KM-1,AE5KM-1", "oob"})
	h.SetRdAuxdata([]string{"oob", "addr:ax25:0,AE5KM-1,AE5KM-1", "pid:33"})
	tstdata := []byte("AX25 Test String")
	h.SetData(tstdata)
	rv = h.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for data: " + gensio.ErrToStr(rv))
	}

	g.CloseS()
	r.CloseS()
	r.ShutdownS()
	g = nil
	h = nil
	o = nil
	r = nil

	testbase.TestShutdown()
}
