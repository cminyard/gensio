
package testbase

import "fmt"
import "github.com/cminyard/go/gensio"
import "runtime"

// Count of allocated objects
var ObjCount uint32 = 2 // For the OsFuncs and LogHandler blow

type LogHandler struct {
	gensio.LoggerBase
}

func (l *LogHandler) Log(level int, log string) {
	fmt.Printf("LOG(%s): %s\n", gensio.LogLevelToStr(level), log)
}

var O *gensio.OsFuncs = gensio.NewOsFuncs(&LogHandler{})

type ReflEvent interface {
	gensio.SerialEvent
	BreakLinks()
	setup(r Reflector, w *gensio.Waiter)
	setGensio(g gensio.Gensio)
}

type ReflEvHnd struct {
	gensio.SerialEventBase
	G gensio.Gensio
	r Reflector
	err int
	data []byte
}

func (re *ReflEvHnd) setGensio(g gensio.Gensio) {
	re.G = g
}

func (re *ReflEvHnd) setup(r Reflector, w *gensio.Waiter) {
	re.r = r
}

func (re *ReflEvHnd) BreakLinks() {
	re.r = nil
	re.G = nil
}

func (re *ReflEvHnd) Read(err int, data []byte, auxdata []string) uint64 {
	re.G.SetReadCallbackEnable(false)
	if err != 0 {
		if err != gensio.GE_REMCLOSE {
			re.err = err
		}
		re.G = nil
		re.r = nil
		return 0
	}
	re.data = data
	re.G.SetWriteCallbackEnable(true)
	return uint64(len(data))
}

func (re *ReflEvHnd) WriteReady() {
	if re.data == nil {
		re.G.SetWriteCallbackEnable(false)
		return
	}
	count := re.G.Write(re.data, nil)
	if count == uint64(len(re.data)) {
		re.data = nil
		re.G.SetWriteCallbackEnable(false)
		re.G.SetReadCallbackEnable(true)
	} else {
		re.data = re.data[count:]
	}
}

type ReflShutdownDone struct {
	gensio.AccepterShutdownDoneBase
	r Reflector
}

func (rsd *ReflShutdownDone) AccShutdownDone() {
	rsd.r.accShutdownDone()
}

type ReflEnableDone struct {
	gensio.AccepterEnableDoneBase
	r Reflector
}

func (red *ReflEnableDone) AccEnableDone() {
	red.r.accEnableDone()
}

type Reflector interface {
	gensio.AccepterEvent
	Init(o *gensio.OsFuncs, accstr string, evh ReflEvent, cb Reflector)
	CloseS()
	Startup()
	SetEnable(val bool)
	SetEnableS(val bool)
	SetEnableCb(val bool)
	accEnableDone()
	Shutdown()
	accShutdownDone()
	ShutdownS()
	GetPort() string
	breakLinks()
	Wait(count uint, timeout *gensio.Time) int

	GetAccepter() gensio.Accepter
	GetGensio() gensio.Gensio
}

type ReflectorBase struct {
	gensio.AccepterEventBase

	evh ReflEvent
	w *gensio.Waiter
	acc gensio.Accepter
	g gensio.Gensio
}

func (r *ReflectorBase) Log(level int, log string) {
	fmt.Printf("AccLOG(%s): %s\n", gensio.LogLevelToStr(level), log)
}

func (r *ReflectorBase) GetAccepter() gensio.Accepter {
	return r.acc
}

func (r *ReflectorBase) GetGensio() gensio.Gensio {
	return r.g
}

func (r *ReflectorBase) Init(o *gensio.OsFuncs, accstr string, evh ReflEvent,
		cb Reflector) {
	ObjCount++
	r.w = gensio.NewWaiter(o)
	if evh == nil {
		ObjCount++
		evh = &ReflEvHnd{}
	}
	evh.setup(r, r.w) // Circ ref, make sure to break
	r.evh = evh
	ObjCount++
	r.acc = gensio.NewAccepter(accstr, o, cb)
}

func NewReflector(o *gensio.OsFuncs, accstr string, evh ReflEvent) Reflector {
	r := &ReflectorBase{}
	r.Init(o, accstr, evh, r)
	return r
}

func (r *ReflectorBase) NewConnection(g gensio.Gensio) {
	if r.g != nil {
		return
	}
	ObjCount++
	r.g = g
	r.evh.setGensio(g)
	g.SetEvent(r.evh)
	g.SetReadCallbackEnable(true)
}

func (r *ReflectorBase) CloseS() {
	r.g.CloseS()
	r.g = nil
}

func (r *ReflectorBase) Startup() {
	r.acc.Startup()
}

func (r *ReflectorBase) SetEnable(val bool) {
	r.acc.SetCallbackEnable(val, nil)
}

func (r *ReflectorBase) SetEnableS(val bool) {
	r.acc.SetCallbackEnableS(val)
}

func (r *ReflectorBase) SetEnableCb(val bool) {
	ObjCount++
	red := &ReflEnableDone{}
	red.r = r
	r.acc.SetCallbackEnable(val, red)
}

func (r *ReflectorBase) accEnableDone() {
	r.w.Wake()
}

func (r *ReflectorBase) Shutdown() {
	ObjCount++
	reh := &ReflShutdownDone{}
	reh.r = r
	r.acc.Shutdown(reh)
}

func (r *ReflectorBase) accShutdownDone() {
	r.w.Wake()
	r.breakLinks()
}

func (r *ReflectorBase) ShutdownS() {
	r.acc.ShutdownS()
	r.breakLinks()
}

func (r *ReflectorBase) GetPort() string {
	return r.acc.GetPort()
}

func (r *ReflectorBase) breakLinks() {
	r.evh.BreakLinks()
	r.evh = nil
	r.g = nil
	r.acc = nil
}

func (r *ReflectorBase) Wait(count uint, timeout *gensio.Time) int {
	return r.w.Wait(count, timeout)
}

func Cmpbytes(b1 []byte, b2 []byte) bool {
	if len(b1) != len(b2) {
		return false
	}
	for i, v := range b1 {
		if b2[i] != v {
			return false
		}
	}
	return true
}

type Event interface {
	gensio.Event
	Setup(o *gensio.OsFuncs)
	SetGensio(g gensio.Gensio)
}

type EvHnd struct {
	gensio.SerialEventBase
	o *gensio.OsFuncs
	Data []byte
	Readpos int
	Writepos int
	G gensio.Gensio
	W *gensio.Waiter
}

func (eh *EvHnd) Setup(o *gensio.OsFuncs) {
	eh.o = o
	ObjCount++
	eh.W = gensio.NewWaiter(o)
}

func (eh *EvHnd) SetGensio(g gensio.Gensio) {
	eh.G = g
}

func (eh *EvHnd) Read(err int, data []byte, auxdata []string) uint64 {
	readlen := len(data)
	if readlen + eh.Readpos > len(eh.Data) {
		panic("Read too much data")
	}
	if ! Cmpbytes(data, eh.Data[eh.Readpos:eh.Readpos + readlen]) {
		panic("Data mismatch")
	}
	eh.Readpos += readlen
	if eh.Readpos == len(eh.Data) {
		eh.W.Wake()
		eh.G = nil
	}
	return uint64(readlen)
}

func (eh *EvHnd) WriteReady() {
	if eh.Data == nil || eh.Writepos >= len(eh.Data) {
		eh.G.SetWriteCallbackEnable(false)
		return
	}
	count := eh.G.Write(eh.Data[eh.Writepos:], nil)
	eh.Writepos += int(count)
	if eh.Writepos >= len(eh.Data) {
		eh.G.SetWriteCallbackEnable(false)
	}
}

func (eh *EvHnd) SetData(data []byte) {
	eh.Data = data
	eh.Readpos = 0
	eh.Writepos = 0
	eh.G.SetReadCallbackEnable(true)
	eh.G.SetWriteCallbackEnable(true)
}

func (eh *EvHnd) Wait(count uint, timeout *gensio.Time) int {
	return eh.W.Wait(count, timeout)
}

func TestShutdown() {
	ObjCount++
	w := gensio.NewWaiter(O)
	ObjCount++
	t := gensio.NewTime(0, 0)
	for count := 0; gensio.Gensio_num_alloced() > 0; count++ {
		if (count > 100) {
			panic(fmt.Sprintf(
				"All gensios not freed in time, still %d left",
				gensio.Gensio_num_alloced()))
		}
		t.SetTime(0, 1000000)
		w.Service(t)
		runtime.GC()
	}
	w = nil
	O.Set_log_handler(nil)
	runtime.GC()
	runtime.GC()
	for count := 0; O.Get_refcount() != 1; count++ {
		if (count > 100) {
			panic(fmt.Sprintf("OS funcs refcount was not 1, it was %d",
				O.Get_refcount()))
		}
		runtime.GC()
	}
	O.Cleanup_mem()
	O = nil

	for count := 0; gensio.GCCount != ObjCount; count++ {
		if (count > 100) {
			panic(fmt.Sprintf("GC-ed object count was %d, should be %d",
				gensio.GCCount, ObjCount))
		}
		runtime.GC()
	}
}

func VerifyAccepter(acc gensio.Accepter, acctype string, isReliable bool,
		isPacket bool, isMessage bool) {
	if acc.GetType(0) != acctype {
		panic("Accepter type incorrect")
	}
	if acc.IsReliable() != isReliable {
		panic("IsReliable incorrect")
	}
	if acc.IsPacket() != isPacket {
		panic("IsPacket incorrect")
	}
	if acc.IsMessage() != isMessage {
		panic("IsMessage incorrect")
	}
}

func VerifyGensio(g gensio.Gensio, gentype string, isClient bool,
		isReliable bool, isPacket bool, isAuthenticated bool,
		isEncrypted bool, isMessage bool) {
	if g.GetType(0) != gentype {
		panic("Gensio type incorrect")
	}
	if g.IsClient() != isClient {
		panic("IsClient incorrect")
	}
	if g.IsReliable() != isReliable {
		panic("IsReliable incorrect")
	}
	if g.IsPacket() != isPacket {
		panic("IsPacket incorrect")
	}
	if g.IsAuthenticated() != isAuthenticated {
		panic("IsAuthenticated incorrect")
	}
	if g.IsEncrypted() != isEncrypted {
		panic("IsEncrypted incorrect")
	}
	if g.IsMessage() != isMessage {
		panic("IsMessage incorrect")
	}
}
