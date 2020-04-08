cmake_minimum_required(VERSION 3.10)

project(gensio VERSION 2.0.2)
set (gensio_VERSION_STRING "${gensio_VERSION_MAJOR}.${gensio_VERSION_MINOR}.${gensio_VERSION_PATCH}")

include_directories("${PROJECT_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include"
                    "${PROJECT_BINARY_DIR}/include")

include(CheckLibraryExists)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckCSourceCompiles)
include(GNUInstallDirs)

set (CMAKE_C_FLAGS "-Wall")
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

option(USE_UUCP_LOCKING "Enable UUCP lock file handling for devices" ON)

option(ENABLE_TCP_WRAPPERS "Enable tcpwrappers support" ON)
if(ENABLE_TCP_WRAPPERS)
  CHECK_INCLUDE_FILE(tcpd.h HAVE_TCPD_H)
  if(HAVE_TCPD_H)
    list(APPEND EXTRA_LIBS wrap)
   endif()
endif()

option(ENABLE_PTHREADS "Enable pthreads" ON)
set(USE_PTHREADS 0)
if(ENABLE_PTHREADS)
  CHECK_LIBRARY_EXISTS(pthread "pthread_create" "" PTHREAD_LIB_FOUND)
  CHECK_INCLUDE_FILE(pthread.h PTHREAD_INC_FOUND)
  if(PTHREAD_LIB_FOUND AND PTHREAD_INC_FOUND)
    set(USE_PTHREADS 1)
    list(APPEND EXTRA_LIBS pthread)
  endif()
endif()

option(ENABLE_EPOLL "Enable epoll support" ON)
if(ENABLE_EPOLL)
  CHECK_INCLUDE_FILE(sys/epoll.h HAVE_EPOLL_PWAIT)
endif()

option(ENABLE_OPENIPMI "Enable OpenIPMI serial over LAN support" ON)
if(ENABLE_OPENIPMI)
  CHECK_LIBRARY_EXISTS(OpenIPMI "ipmi_alloc_os_handler" "" OPENIPMI_LIB_FOUND)
  CHECK_INCLUDE_FILE(OpenIPMI/ipmiif.h OPENIPMI_INC_FOUND)
  if(OPENIPMI_LIB_FOUND AND OPENIPMI_INC_FOUND)
    set(HAVE_OPENIPMI 1)
    if(USE_PTHREADS)
      list(APPEND EXTRA_LIBS OpenIPMI OpenIPMIpthread OpenIPMIutils)
    else()
      list(APPEND EXTRA_LIBS OpenIPMI OpenIPMIposix OpenIPMIutils)
    endif()
  endif()
endif()

option(ENABLE_OPENSSL "Enable openssl" ON)
set(HAVE_OPENSSL 0)
if(ENABLE_OPENSSL)
  CHECK_LIBRARY_EXISTS(ssl "SSL_connect" "" SSL_LIB_FOUND)
  CHECK_LIBRARY_EXISTS(crypto "X509_verify_cert" "" CRYPTO_LIB_FOUND)
  CHECK_INCLUDE_FILE(openssl/ssl.h SSL_INC_FOUND)
  CHECK_INCLUDE_FILE(openssl/x509.h CRYPTO_INC_FOUND)
  if(SSL_LIB_FOUND AND SSL_INC_FOUND AND CRYPTO_LIB_FOUND AND CRYPTO_INC_FOUND)
    set(HAVE_OPENSSL 1)
    list(APPEND EXTRA_LIBS ssl crypto)
  endif()
endif()

option(ENABLE_SWIG "Enable swig support" ON)
if(ENABLE_SWIG)
  find_package(SWIG)
endif()

option(ENABLE_PYTHON "Enable python support" ON)
if(ENABLE_PYTHON)
  set (Python_ADDITIONAL_VERSIONS 3 2)
  find_package(PythonInterp)
  find_package(PythonLibs)
  # FIXME - we are assuming this for now.
  option(PYTHON_HAS_POSIX_THREADS "Support threading in python" ON)
endif()

option(ENABLE_SCTP "Enable SCTP support" ON)
if(ENABLE_SCTP)
  CHECK_LIBRARY_EXISTS(sctp "sctp_bindx" "" HAVE_LIBSCTP)
  if (HAVE_LIBSCTP)
    list(APPEND EXTRA_LIBS sctp)
  endif()
endif()

CHECK_LIBRARY_EXISTS(pam "pam_start" "" HAVE_PAM)

check_symbol_exists(TIOCSRS485 sys/ioctl.h HAVE_DECL_TIOCSRS485)

CHECK_INCLUDE_FILE(sys/un.h HAVE_UNIX)

option(USE_FILE_STDIO "Use stdio instead of unix files for the file gensio"
       ${MSVC})

option(ENABLE_INTERNAL_TRACE
       "Enable internal trace tools, required for oomtest"
       OFF)

set (prefix "${CMAKE_INSTALL_PREFIX}")
set (exec_prefix "${CMAKE_INSTALL_PREFIX}")
set (libdir "${CMAKE_INSTALL_FULL_LIBDIR}")
set (includedir "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
set (VERSION "${PROJECT_VERSION}")

check_c_source_compiles("int main()
{
	static int counter = 0;
	int val;

	__atomic_load(&counter, &val, __ATOMIC_SEQ_CST);
	return val;
}" HAVE_GCC_ATOMICS)

check_symbol_exists(isatty unistd.h HAVE_ISATTY)
check_symbol_exists(strcasecmp string.h HAVE_STRCASECMP)
check_symbol_exists(strncasecmp string.h HAVE_STRNCASECMP)

if(UNIX)
  set(HAVE_STDIO 1)
  set(HAVE_SERIALDEV 1)
  set(HAVE_PTY 1)
else()
  set(HAVE_STDIO 0)
  set(HAVE_SERIALDEV 0)
  set(HAVE_PTY 0)
endif()

configure_file(config.h.cmake config.h)

add_subdirectory(lib)
add_subdirectory(include)
add_subdirectory(tools)
add_subdirectory(examples)
if(SWIG_FOUND)
  add_subdirectory(swig)
endif()
add_subdirectory(man)
if(UNIX)
add_subdirectory(tests)
endif()

set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME
  "${CMAKE_PROJECT_NAME}-${gensio_VERSION_MAJOR}.${gensio_VERSION_MINOR}.${gensio_VERSION_PATCH}")
set(CPACK_SOURCE_IGNORE_FILES "/.git/;/Z.*/;~$;${CPACK_SOURCE_IGNORE_FILES}")
include(CPack)
add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)
