install(FILES gensio.h gensio_class.h sergensio.h sergensio_class.h
	gensio_selector.h gensio_base.h gensio_acc_gensio.h
	gensio_ll_fd.h gensio_ll_gensio.h selector.h argvutils.h
	gensio_os_funcs.h gensio_err.h gensio_builtins.h gensio_osops.h
	gensio_list.h gensio_dllvisibility.h gensio_deprecated.h gensio_mdns.h
	gensio_types.h gensio_osops_addrinfo.h gensio_osops_stdsock.h
	DESTINATION include/gensio)

configure_file(gensio_version.h.in gensio_version.h)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/gensio_version.h
        DESTINATION include/gensio)
