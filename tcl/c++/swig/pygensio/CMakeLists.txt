if(PYTHON_VERSION_MAJOR EQUAL 3)
  set(SWIG_EXTRA_FLAGS -py3)
endif()
include_directories(${PYTHON_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}
  "${PROJECT_SOURCE_DIR}/c++/include"
  "${PROJECT_SOURCE_DIR}/c++/swig/pygensio"
  "${PROJECT_SOURCE_DIR}/tcl/c++/include"
  "${PROJECT_SOURCE_DIR}/tcl/include"
)
set(CMAKE_SWIG_FLAGS -I${CMAKE_CURRENT_SOURCE_DIR} ${SWIG_EXTRA_FLAGS})
swig_add_library(_pygensiotcl LANGUAGE python SOURCES ../pygensiotcl.i)
swig_link_libraries(_pygensiotcl gensiocpp gensio gensiotcl)
set_target_properties(_pygensiotcl PROPERTIES LIBRARY_OUTPUT_NAME pygensiotcl)

execute_process(COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())" OUTPUT_VARIABLE PYTHON_SITE_PACKAGES OUTPUT_STRIP_TRAILING_WHITESPACE)
set(PYTHON_INSTALL_SITE_PACKAGES ${PYTHON_SITE_PACKAGES} CACHE FILEPATH
    "The path to install Python packages to")
install(TARGETS _pygensiotcl DESTINATION ${PYTHON_INSTALL_SITE_PACKAGES})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pygensiotcl.py DESTINATION ${PYTHON_INSTALL_SITE_PACKAGES})
