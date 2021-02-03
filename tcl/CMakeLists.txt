
set(LIBFILES gensio_tcl.c)

add_library(gensiotcl ${LIBFILES})
if(BUILD_SHARED_LIBS AND ALSOSTATIC)
  add_library(gensiotcl-static STATIC ${LIBFILES})
  SET_TARGET_PROPERTIES(gensiotcl-static PROPERTIES OUTPUT_NAME gensiotcl
                        CLEAN_DIRECT_OUTPUT 1)
  install(TARGETS gensiotcl-static DESTINATION lib)
endif()
target_link_libraries(gensiotcl ${TCL_LIBRARY})
set_property(TARGET gensiotcl PROPERTY VERSION 0.0.0)
set_property(TARGET gensiotcl PROPERTY SOVERSION 0)

install(TARGETS gensiotcl DESTINATION lib EXPORT gensiotcl)
install(EXPORT gensiotcl FILE gensiotcl.cmake DESTINATION lib/cmake/gensio)
set_target_properties(gensiotcl PROPERTIES COMPILE_FLAGS "-DBUILDING_DLL")
if (WIN32)
  # Stick this in the directories so Windows can find it when running
  # gensiot and oomtest.  Probably not right, but works for now.
  install(TARGETS gensio DESTINATION bin)
endif()
target_include_directories(gensiotcl
                           INTERFACE
                            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                            $<INSTALL_INTERFACE:include>
                           )
target_include_directories(gensiotcl PUBLIC ${TCL_INCLUDE_PATH})
include_directories("include")

if(SWIG_FOUND)
  add_subdirectory(swig)
endif()

configure_file(libgensiotcl.pc.in libgensiotcl.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libgensiotcl.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
