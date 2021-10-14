
add_library(gensiotool STATIC ioinfo.c ser_ioinfo.c utils.c localports.c
	    file_utils.c run_get_output.c)
set_target_properties(gensiotool PROPERTIES
                      POSITION_INDEPENDENT_CODE OFF)

include_directories("${PROJECT_SOURCE_DIR}/glib/include"
		    "${PROJECT_SOURCE_DIR}/tcl/include")

add_executable(gensiot gensiotool.c)
target_link_libraries(gensiot gensio gensiotool ${GLIB_LIB} ${GLIB_LDFLAGS}
		      ${TCL_LIB} ${TCL_LIBS})

install(TARGETS gensiot DESTINATION bin)

install(FILES gensiot.1 DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man1)

add_library(gtlssh-shared STATIC gtlssh-shared.c)

if(HAVE_OPENSSL)
  add_executable(gtlssh-keygen gtlssh-keygen.c)
  target_link_libraries(gtlssh-keygen gensiotool gtlssh-shared crypto gensio)
endif()

if(HAVE_AVAHI)
  add_executable(gmdns gensiomdns.c)
  target_link_libraries(gmdns gensio gensiotool)
  install(TARGETS gmdns DESTINATION bin)
  install(FILES gmdns.1 DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man1)
endif()

if(UNIX)
  set_target_properties(gensiotool PROPERTIES
                        POSITION_INDEPENDENT_CODE OFF)

  set (SYSCONFDIR, "${CMAKE_INSTALL_FULL_SYSCONFDIR}")

  add_executable(gtlssh gtlssh.c)
  target_link_libraries(gtlssh gensio gtlssh-shared gensiotool)

  install(TARGETS gtlssh DESTINATION bin)
  install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/gtlssh-keygen DESTINATION bin)
  install(PROGRAMS gtlssync DESTINATION bin)

  install(FILES gtlssh.1 DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man1)
  install(FILES gtlssync.1 DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man1)
  install(FILES gtlssh-keygen.1 DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man1)

  if(HAVE_PAM)
    add_executable(gtlsshd gtlsshd.c)
    target_compile_definitions(gtlsshd PRIVATE "SYSCONFDIR=\"${CMAKE_INSTALL_FULL_SYSCONFDIR}\"")
    target_link_libraries(gtlsshd gensio gtlssh-shared gensiotool pam)
    install(TARGETS gtlsshd DESTINATION sbin)
    install(FILES gtlsshd.8 DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man8)
  endif()
endif()
