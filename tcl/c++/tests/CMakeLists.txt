
enable_testing()

include_directories("${PROJECT_SOURCE_DIR}/c++/include"
  "${PROJECT_SOURCE_DIR}/tcl/c++/include"
  )

add_executable(basic_tcl basic_tcl.cc)
target_link_libraries(basic_tcl gensio gensiocpp gensiotcl)

add_test(NAME basic_tcl
         COMMAND basic_tcl)
set_tests_properties(basic_tcl PROPERTIES SKIP_RETURN_CODE 77)
