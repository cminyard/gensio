add_executable(basic_client basic_client.c)
target_link_libraries(basic_client gensio)

add_executable(basic_server basic_server.c)
target_link_libraries(basic_server gensio)

add_executable(basic_server_sync basic_server_sync.c)
target_link_libraries(basic_server_sync gensio)

if(UNIX)
add_executable(basic_server_sync_fork basic_server_sync_fork.c)
target_link_libraries(basic_server_sync_fork gensio)
endif()

add_executable(sound sound.c)
target_link_libraries(sound gensio gensiotool)
