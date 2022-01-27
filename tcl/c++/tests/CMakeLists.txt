
enable_testing()

include_directories("${PROJECT_SOURCE_DIR}/c++/include"
  "${PROJECT_SOURCE_DIR}/tcl/c++/include"
  )

add_executable(basic_tcl_test basic_tcl_test.cc)
target_link_libraries(basic_tcl_test gensio gensiocpp gensiotcl)

add_test(NAME basic_tcl_test
         COMMAND basic_tcl_test)
set_tests_properties(basic_tcl_test PROPERTIES SKIP_RETURN_CODE 77)
