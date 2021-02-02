set(LIBFILES gensio_python_swig.c)

add_library(gensio_python_swig ${LIBFILES})
if(BUILD_SHARED_LIBS AND ALSOSTATIC)
  add_library(gensio_python_swig-static STATIC ${LIBFILES})
  SET_TARGET_PROPERTIES(gensio_python_swig-static PROPERTIES OUTPUT_NAME gensio_python_swig
                        CLEAN_DIRECT_OUTPUT 1)
  install(TARGETS gensio_python_swig-static DESTINATION lib)
endif()
target_link_libraries(gensio_python_swig ${EXTRA_LIBS})
set_property(TARGET gensio_python_swig PROPERTY VERSION 0.0.0)
set_property(TARGET gensio_python_swig PROPERTY SOVERSION 0)

install(TARGETS gensio_python_swig DESTINATION lib EXPORT gensio_python_swig)
install(EXPORT gensio_python_swig FILE gensio_python_swig.cmake DESTINATION lib/cmake/gensio)
set_target_properties(gensio_python_swig PROPERTIES COMPILE_FLAGS "-DBUILDING_DLL")
if (WIN32)
  # Stick this in the directories so Windows can find it when running
  # gensiot and oomtest.  Probably not right, but works for now.
  install(TARGETS gensio DESTINATION bin)
endif()
target_include_directories(gensio_python_swig
                           INTERFACE
                            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                            $<INSTALL_INTERFACE:include>
                           )

configure_file(libgensio_python_swig.pc.in libgensio_python_swig.pc @ONLY)

if(PYTHON_VERSION_MAJOR EQUAL 3)
  set(SWIG_EXTRA_FLAGS -py3)
endif()
include_directories(${PYTHON_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_SWIG_FLAGS -I${CMAKE_CURRENT_SOURCE_DIR} ${SWIG_EXTRA_FLAGS})
swig_add_library(gensio LANGUAGE python SOURCES ../gensio.i)
swig_link_libraries(gensio gensio)

execute_process(COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())" OUTPUT_VARIABLE PYTHON_SITE_PACKAGES OUTPUT_STRIP_TRAILING_WHITESPACE)
set(PYTHON_INSTALL_SITE_PACKAGES ${PYTHON_SITE_PACKAGES} CACHE FILEPATH
    "The path to install Python packages to")
install(TARGETS _gensio DESTINATION ${PYTHON_INSTALL_SITE_PACKAGES})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/gensio.py DESTINATION ${PYTHON_INSTALL_SITE_PACKAGES})
