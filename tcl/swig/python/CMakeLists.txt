if(PYTHON_VERSION_MAJOR EQUAL 3)
  set(SWIG_EXTRA_FLAGS -py3)
endif()
include_directories(${PYTHON_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}
		    "${PROJECT_SOURCE_DIR}/tcl/include"
		    "${PROJECT_SOURCE_DIR}/swig/include")
set(SWIG_INCLUDE_DIRECTORIES TRUE)
set(CMAKE_SWIG_FLAGS -I${CMAKE_CURRENT_SOURCE_DIR} ${SWIG_EXTRA_FLAGS})
swig_add_library(_gensiotcl LANGUAGE python SOURCES ../gensiotcl.i)
swig_link_libraries(_gensiotcl gensio)
swig_link_libraries(_gensiotcl gensiotcl)

execute_process(COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())" OUTPUT_VARIABLE PYTHON_SITE_PACKAGES OUTPUT_STRIP_TRAILING_WHITESPACE)
set(PYTHON_INSTALL_SITE_PACKAGES ${PYTHON_SITE_PACKAGES} CACHE FILEPATH
    "The path to install Python packages to")
install(TARGETS _gensiotcl DESTINATION ${PYTHON_INSTALL_SITE_PACKAGES})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/gensiotcl.py DESTINATION ${PYTHON_INSTALL_SITE_PACKAGES})
