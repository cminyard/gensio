option(ALSOSTATIC "When buiding a shared library, build a static one, too")

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
  gensio_osops.c
  sergensio_telnet.c
  gensio_filter_certauth.c
  telnet.c
  gensio_filter_msgdelim.c
  gensio_relpkt.c
  utils.c
  gensio_filter_relpkt.c
  gensio_sctp.c
  gensio_filter_ssl.c
  gensio_selector.c
  waiter.c)

set(UNIX_LIBFILES
  gensio_stdio.c
  gensio_ll_fd.c
  selector.c
  sergensio_serialdev.c
  uucplock.c
  gensio_pty.c)

if(UNIX)
  set(LIBFILES ${BASE_LIBFILES} ${UNIX_LIBFILES})
  set(HAVE_STDIO 1)
  set(HAVE_SERIALDEV 1)
  set(HAVE_PTY 1)
else()
  set(LIBFILES ${BASE_LIBFILES})
  set(HAVE_STDIO 0)
  set(HAVE_SERIALDEV 0)
  set(HAVE_PTY 0)
endif()

add_library(gensio ${LIBFILES})
if(BUILD_SHARED_LIBS AND ALSOSTATIC)
  add_library(gensio-static STATIC ${LIBFILES})
  SET_TARGET_PROPERTIES(gensio-static PROPERTIES OUTPUT_NAME gensio
                        CLEAN_DIRECT_OUTPUT 1)
  install(TARGETS gensio-static DESTINATION lib)
endif()
target_link_libraries(gensio ${EXTRA_LIBS})
set_property(TARGET gensio PROPERTY VERSION 0.0.0)
set_property(TARGET gensio PROPERTY SOVERSION 0)

install(TARGETS gensio DESTINATION lib EXPORT gensio)
install(EXPORT gensio FILE gensio.cmake DESTINATION lib/cmake/gensio)
target_include_directories(gensio
                           INTERFACE
                            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                            $<INSTALL_INTERFACE:include>
                           )

configure_file(libgensio.pc.in libgensio.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libgensio.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
