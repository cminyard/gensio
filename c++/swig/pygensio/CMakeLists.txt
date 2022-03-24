set(SWIG_EXTRA_FLAGS -py3 -c++)
include_directories(${PYTHON_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}
  "${PROJECT_SOURCE_DIR}/c++/include"
  "${PROJECT_SOURCE_DIR}/c++/swig/include"
  "${PROJECT_SOURCE_DIR}/c++/swig/pygensio"
)
set(CMAKE_SWIG_FLAGS -I${CMAKE_CURRENT_SOURCE_DIR} ${SWIG_EXTRA_FLAGS})
set_property(SOURCE pygensio.i PROPERTY CPLUSPLUS ON)
swig_add_library(_pygensio LANGUAGE python SOURCES pygensio.i)
swig_link_libraries(_pygensio gensiocpp gensio gensioglib)
set_target_properties(_pygensio PROPERTIES LIBRARY_OUTPUT_NAME pygensio)

execute_process(COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())" OUTPUT_VARIABLE PYTHON_SITE_PACKAGES OUTPUT_STRIP_TRAILING_WHITESPACE)
set(PYTHON_INSTALL_SITE_PACKAGES ${PYTHON_SITE_PACKAGES} CACHE FILEPATH
    "The path to install Python packages to")
install(TARGETS _pygensio DESTINATION ${PYTHON_INSTALL_SITE_PACKAGES})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pygensio.py DESTINATION ${PYTHON_INSTALL_SITE_PACKAGES})
