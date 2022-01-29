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

type CryptoReflector struct {
	testbase.ReflectorBase
}

func (r *CryptoReflector) AuthBegin(g gensio.Gensio) int {
	fmt.Println("Auth Begin")
	namedata := make([]byte, 256)
	rv, name, actlen := g.Control(gensio.GENSIO_CONTROL_DEPTH_FIRST, true,
		gensio.GENSIO_CONTROL_USERNAME, namedata)
	if rv != 0 {
		panic("Error from control: " + gensio.ErrToStr(rv))
	}
	if actlen > 256 {
		panic("name data too large")
	}
	if string(name) != "asdf" {
		panic("Name mismatch")
	}
	return gensio.GE_NOTSUP
}

func (r *CryptoReflector) PrecertVerify(g gensio.Gensio) int {
	fmt.Println("Precert Verify")
	return gensio.GE_NOTSUP
}

func (r *CryptoReflector) PostcertVerify(g gensio.Gensio,
		err int, errstr string) int {
	fmt.Println("Postcert Verify")
	return gensio.GE_NOTSUP
}

func (r *CryptoReflector) PasswordVerify(g gensio.Gensio, password string) int {
	fmt.Println("Password Verify")
	if password != "jkl" {
		panic("Password mismatch")
	}
	return gensio.GE_NOTSUP
}

func (r *CryptoReflector) RequestPassword(g gensio.Gensio,
		maxsize uint64) (int, string) {
	fmt.Println("Request Password")
	return 0, "jkl"
}

func (r *CryptoReflector) Verify2fa(g gensio.Gensio, val []byte) int {
	fmt.Println("Verify 2fa")
	if string(val) != "1234" {
		panic("2fa mismatch")
	}
	return 0
}

func (r *CryptoReflector) Request2fa(g gensio.Gensio) (int, []byte) {
	fmt.Println("Request 2fa")
	return 0, []byte("1234")
}

type CryptoEvFuncs struct {
}

func (r *CryptoEvFuncs) PrecertVerify() int {
	fmt.Println("Precert Verify 2")
	return gensio.GE_NOTSUP
}

func (r *CryptoEvFuncs) PostcertVerify(err int, errstr string) int {
	fmt.Println("Postcert Verify 2")
	return gensio.GE_NOTSUP
}

func (r *CryptoEvFuncs) PasswordVerify(password string) int {
	fmt.Println("Password Verify 2")
	if password != "jkl" {
		panic("Password mismatch")
	}
	return gensio.GE_NOTSUP
}

func (r *CryptoEvFuncs) RequestPassword(maxsize uint64) (int, string) {
	fmt.Println("Request Password 2")
	return 0, "jkl"
}

func (r *CryptoEvFuncs) Verify2fa(val []byte) int {
	fmt.Println("Verify 2fa 2")
	if string(val) != "1234" {
		panic("2fa mismatch")
	}
	return 0
}

func (r *CryptoEvFuncs) Request2fa() (int, []byte) {
	fmt.Println("Request 2fa 2")
	return 0, []byte("1234")
}

type CryptoEvHnd struct {
	testbase.EvHnd
	CryptoEvFuncs
}

// Since this references r.G this can't be in CryptoEvFuncs.
func (r *CryptoEvHnd) AuthBegin() int {
	fmt.Println("Auth Begin 2")
	namedata := make([]byte, 256)
	rv, name, actlen := r.G.Control(gensio.GENSIO_CONTROL_DEPTH_FIRST, true,
		gensio.GENSIO_CONTROL_USERNAME, namedata)
	if rv != 0 {
		panic("Error from control: " + gensio.ErrToStr(rv))
	}
	if actlen > 256 {
		panic("Name data too large")
	}
	if string(name) != "asdf" {
		panic("Name mismatch")
	}
	return gensio.GE_NOTSUP
}

func testCryptoForward(o *gensio.OsFuncs) {
	fmt.Println("Testing Crypto forward interface")

	testbase.ObjCount++
	r := &CryptoReflector{}
	r.Init(o,
		"certauth(enable-password,enable-2fa)," +
                "ssl(key=ca/key.pem,cert=ca/cert.pem),tcp,0",
		nil, r)
	r.Startup()
	port := r.GetPort()

	testbase.ObjCount++
	h := &CryptoEvHnd{}
	h.Setup(o)
	testbase.ObjCount++
	g := gensio.NewGensio("certauth(username=asdf,enable-password)," +
		"ssl(ca=ca/CA.pem),tcp,localhost," + port,
		o, h)
	h.SetGensio(g)

	g.OpenS()

	testbase.VerifyAccepter(r.GetAccepter(), "certauth", true, true, false)
	testbase.VerifyGensio(g, "certauth",
		true, true, true, true, true, false)

	tstdata := []byte("Crypto Test String")
	h.SetData(tstdata)
	testbase.ObjCount++
	rv := h.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for data: " + gensio.ErrToStr(rv))
	}

	g.CloseS()
	r.CloseS()
	r.ShutdownS()
}

type CryptoReflEvHnd struct {
	testbase.ReflEvHnd
	CryptoEvFuncs
}

// Since this references r.G this can't be in CryptoEvFuncs.
func (r *CryptoReflEvHnd) AuthBegin() int {
	fmt.Println("Auth Begin 2")
	rv, name, actlen := r.G.Control(gensio.GENSIO_CONTROL_DEPTH_FIRST, true,
		gensio.GENSIO_CONTROL_USERNAME, []byte("0"))
	if rv != 0 {
		panic("Error from control: " + gensio.ErrToStr(rv))
	}
	if actlen > 256 {
		panic("Name data too large")
	}
	if string(name) != "asdf" {
		panic("Name mismatch")
	}
	return gensio.GE_NOTSUP
}

func testCryptoBackward(o *gensio.OsFuncs) {
	fmt.Println("Testing Crypto forward interface")

	testbase.ObjCount++
	hr := &CryptoReflEvHnd{}
	testbase.ObjCount++
	r := &CryptoReflector{}
	r.Init(o,
		"certauth(username=asdf,enable-password,mode=client)," +
                "ssl(ca=ca/CA.pem,mode=client),tcp,0",
		hr, r)
	r.Startup()
	port := r.GetPort()

	testbase.ObjCount++
	h := &CryptoEvHnd{}
	h.Setup(o)
	testbase.ObjCount++
	g := gensio.NewGensio(
		"certauth(enable-password,enable-2fa,mode=server)," +
		"ssl(key=ca/key.pem,cert=ca/cert.pem,mode=server),tcp,localhost," + port,
		o, h)
	h.SetGensio(g)

	testbase.VerifyAccepter(r.GetAccepter(), "certauth", true, true, false)

	g.OpenS()

	testbase.VerifyGensio(g, "certauth",
		false, true, true, true, true, false)

	tstdata := []byte("Crypto Test String")
	h.SetData(tstdata)
	testbase.ObjCount++
	rv := h.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for data: " + gensio.ErrToStr(rv))
	}

	g.CloseS()
	r.CloseS()
	r.ShutdownS()
}

func main() {
	fmt.Println("Starting Crypto Go tests")
	o := testbase.O
	gensio.SetLogMask(gensio.LOG_MASK_ALL)

	testCryptoForward(o)
	testCryptoBackward(o)

	testbase.TestShutdown()
}
