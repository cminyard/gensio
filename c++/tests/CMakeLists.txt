
enable_testing()

include_directories("${PROJECT_SOURCE_DIR}/c++/include")

add_executable(basic_cpp_test basic_cpp_test.cc)
target_link_libraries(basic_cpp_test gensio gensiocpp)

add_executable(serial_test serial_test.cc)
target_link_libraries(serial_test gensio gensiocpp)

add_test(NAME basic_cpp_test
         COMMAND basic_cpp_test)
set_tests_properties(basic_cpp_test PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME serial_test
         COMMAND serial_test)
set_tests_properties(serial_test PROPERTIES SKIP_RETURN_CODE 77)
