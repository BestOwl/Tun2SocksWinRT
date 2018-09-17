add_executable(badvpn-tuntest
	tuntest.c
)

target_link_libraries(badvpn-tuntest libsodium badvpn-tun2socks system flow tuntap lwip socksclient udpgw_client)

add_custom_command(
    TARGET badvpn-tuntest
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:libsodium>
        $<TARGET_FILE_DIR:badvpn-tuntest>/$<TARGET_FILE_NAME:libsodium>
)