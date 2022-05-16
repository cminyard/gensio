
include_directories("${PROJECT_SOURCE_DIR}/c++/include")

set(CPPLIBFILES gensio.cc)

add_library(gensiocpp ${CPPLIBFILES})
target_link_libraries(gensiocpp gensio)
set_target_properties(gensiocpp PROPERTIES COMPILE_FLAGS "-DBUILDING_GENSIOCPP_DLL")
if(BUILD_SHARED_LIBS AND ALSOSTATIC)
  add_library(gensiocpp-static STATIC ${CPPLIBFILES})
  SET_TARGET_PROPERTIES(gensiocpp-static PROPERTIES OUTPUT_NAME gensiocpp
                        CLEAN_DIRECT_OUTPUT 1)
  install(TARGETS gensiocpp-static DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
set_property(TARGET gensiocpp PROPERTY VERSION 1.1.0)
set_property(TARGET gensiocpp PROPERTY SOVERSION 1)
install(TARGETS gensiocpp DESTINATION ${CMAKE_INSTALL_LIBDIR} EXPORT gensiocpp)
configure_file(libgensiocpp.pc.in libgensiocpp.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libgensiocpp.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
