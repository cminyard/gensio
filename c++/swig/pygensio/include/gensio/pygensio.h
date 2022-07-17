
#ifndef __PYGENSIO_H__
#define __PYGENSIO_H__

// Increment/decrement refcount for object contained in directors.
// If the python code passed a reference in then loses all it's
// reference to it, we want to make sure it still hangs around.
void pydirobj_incref(Swig::Director *dir)
{
    PyObject *po = dir->swig_get_self();

    /* Make sure it's not deleted if python loses all references. */
    Py_INCREF(po);
}
void pydirobj_decref(Swig::Director *dir)
{
    PyObject *po = dir->swig_get_self();

    /* Make sure it's not deleted if python loses all references. */
    Py_DECREF(po);
}

class Internal_Log_Handler : public gensios::Os_Funcs_Log_Handler {
 public:
 Internal_Log_Handler(gensios::Os_Funcs_Log_Handler *pyhandler):
		handler(pyhandler) {
	if (handler)
	    pydirobj_incref(dynamic_cast<Swig::Director *>(handler));
    }

    virtual ~Internal_Log_Handler() {
	if (handler)
	    pydirobj_decref(dynamic_cast<Swig::Director *>(handler));
    }

    void set_handler(gensios::Os_Funcs_Log_Handler *pyhandler) {
	if (handler)
	    pydirobj_decref(dynamic_cast<Swig::Director *>(handler));
	handler = pyhandler;
	if (handler)
	    pydirobj_incref(dynamic_cast<Swig::Director *>(handler));
    }

    void log(enum gensios::gensio_log_levels level, const std::string log) override {
	// Hack.  If there is a python error, the call to the log
	// function will always fail because this error is not
	// cleared and SWIG will think the log call failed.  This
	// will print some useful information and clear the error
	// log.
	PyErr_Print();

	if (handler)
	    handler->log(level, log);
    }

 private:
    gensios::Os_Funcs_Log_Handler *handler;
};

#endif /* __PYGENSIO_H__ */
