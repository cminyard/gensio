include_directories("${PROJECT_SOURCE_DIR}/c++/include")

add_executable(telnet_server telnet_server.cc)
target_link_libraries(telnet_server gensio gensiocpp)
