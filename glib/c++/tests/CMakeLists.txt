
enable_testing()

include_directories("${PROJECT_SOURCE_DIR}/c++/include"
  "${PROJECT_SOURCE_DIR}/glib/c++/include"
  )

add_executable(basic_glib_test basic_glib_test.cc)
target_link_libraries(basic_glib_test gensio gensiocpp gensioglib ${GLIB_LIBS})

add_test(NAME basic_glib_test
         COMMAND basic_glib_test)
set_tests_properties(basic_glib_test PROPERTIES SKIP_RETURN_CODE 77)
