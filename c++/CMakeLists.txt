
include_directories("${PROJECT_SOURCE_DIR}/c++/include")

set(CPPLIBFILES gensio.cc)

add_library(gensiocpp ${CPPLIBFILES})
if(BUILD_SHARED_LIBS AND ALSOSTATIC)
  add_library(gensiocpp-static STATIC ${CPPLIBFILES})
  SET_TARGET_PROPERTIES(gensiocpp-static PROPERTIES OUTPUT_NAME gensiocpp
                        CLEAN_DIRECT_OUTPUT 1)
  install(TARGETS gensiocpp-static DESTINATION lib)
endif()
set_property(TARGET gensiocpp PROPERTY VERSION 0.0.0)
set_property(TARGET gensiocpp PROPERTY SOVERSION 0)
install(TARGETS gensiocpp DESTINATION lib EXPORT gensiocpp)
configure_file(libgensiocpp.pc.in libgensiocpp.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libgensiocpp.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

add_subdirectory(include)
add_subdirectory(tests)
add_subdirectory(examples)
