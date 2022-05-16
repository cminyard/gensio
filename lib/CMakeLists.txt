set(BASE_LIBFILES
  buffer.c
  gensio_net.c
  gensio_filter_telnet.c
  gensio_ssl.c
  gensio_acc.c
  gensio_filter_trace.c
  gensio_acc_gensio.c
  gensio_trace.c
  gensio_base.c
  gensio_ll_gensio.c
  gensio_ll_fd.c
  gensio_udp.c
  gensio.c
  gensio_ll_ipmisol.c
  gensio_certauth.c
  gensio_msgdelim.c
  sergensio.c
  gensio_dummy.c
  gensio_mux.c
  sergensio_ipmisol.c
  gensio_echo.c
  gensio_file.c
  sergensio_telnet.c
  gensio_filter_certauth.c
  telnet.c
  gensio_filter_msgdelim.c
  gensio_relpkt.c
  utils.c
  gensio_filter_relpkt.c
  gensio_sctp.c
  gensio_filter_ssl.c
  gensio_perf.c
  gensio_filter_perf.c
  gensio_conacc.c
  mdns.c
  avahi_watcher.c
  gensio_mdns.c
  gensio_stdio.c
  sergensio_serialdev.c
  gensio_circbuf.c
  gensio_addrinfo.c
  gensio_stdsock.c
  uucplock.c
  gensio_pty.c
  gensio_osops.c
  gensio_osops_env.c
  gensio_filter_kiss.c
  gensio_kiss.c
  crc16.c
  gensio_ax25_addr.c
  gensio_ax25.c
  gensio_filter_xlt.c
  gensio_xlt.c
  gensio_keepopen.c
  )

set(UNIX_LIBFILES
  selector.c
  gensio_unix.c)

set(WINDOWS_LIBFILES
  gensio_win.c)

if(ENABLE_INTERNAL_TRACE)
  set(ERRTRIG_LIBFILES errtrig.c)
else()
  set(ERRTRIG_LIBFILES)
endif()

if(UNIX)
  set(LIBFILES ${BASE_LIBFILES} ${UNIX_LIBFILES} ${ERRTIRG_LIBFILES})
else()
  set(LIBFILES ${BASE_LIBFILES} ${WINDOWS_LIBFILES} ${ERRTRIG_LIBFILES})
endif()

add_library(gensio ${LIBFILES})
if(BUILD_SHARED_LIBS AND ALSOSTATIC)
  add_library(gensio-static STATIC ${LIBFILES})
  SET_TARGET_PROPERTIES(gensio-static PROPERTIES OUTPUT_NAME gensio
                        CLEAN_DIRECT_OUTPUT 1)
  install(TARGETS gensio-static DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
target_link_libraries(gensio ${EXTRA_LIBS})
set_property(TARGET gensio PROPERTY VERSION 1.0.1)
set_property(TARGET gensio PROPERTY SOVERSION 1)

install(TARGETS gensio DESTINATION ${CMAKE_INSTALL_LIBDIR} EXPORT gensio)
install(EXPORT gensio FILE gensio.cmake DESTINATION lib/cmake/gensio)
set_target_properties(gensio PROPERTIES COMPILE_FLAGS "-DBUILDING_GENSIO_DLL")
if (WIN32)
  # Stick this in the directories so Windows can find it when running
  # gensiot and oomtest.  Probably not right, but works for now.
  install(TARGETS gensio DESTINATION bin)
endif()
target_include_directories(gensio
                           INTERFACE
                            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                            $<INSTALL_INTERFACE:include>
                           )

configure_file(libgensio.pc.in libgensio.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libgensio.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
