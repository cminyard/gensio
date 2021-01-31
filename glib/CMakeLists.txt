
set(LIBFILES gensio_glib.c)

add_library(gensioglib ${LIBFILES})
if(BUILD_SHARED_LIBS AND ALSOSTATIC)
  add_library(gensioglib-static STATIC ${LIBFILES})
  SET_TARGET_PROPERTIES(gensioglib-static PROPERTIES OUTPUT_NAME gensioglib
                        CLEAN_DIRECT_OUTPUT 1)
  install(TARGETS gensioglib-static DESTINATION lib)
endif()
target_link_libraries(gensioglib ${EXTRA_LIBS})
set_property(TARGET gensioglib PROPERTY VERSION 0.0.0)
set_property(TARGET gensioglib PROPERTY SOVERSION 0)

install(TARGETS gensioglib DESTINATION lib EXPORT gensioglib)
install(EXPORT gensioglib FILE gensioglib.cmake DESTINATION lib/cmake/gensio)
set_target_properties(gensioglib PROPERTIES COMPILE_FLAGS "-DBUILDING_DLL")
if (WIN32)
  # Stick this in the directories so Windows can find it when running
  # gensiot and oomtest.  Probably not right, but works for now.
  install(TARGETS gensio DESTINATION bin)
endif()
target_include_directories(gensioglib
                           INTERFACE
                            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                            $<INSTALL_INTERFACE:include>
                           )
target_include_directories(gensioglib PUBLIC ${GLIB_INCLUDE_DIRS})

if(SWIG_FOUND)
  add_subdirectory(swig)
endif()

configure_file(libgensioglib.pc.in libgensioglib.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libgensioglib.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
