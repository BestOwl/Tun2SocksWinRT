add_executable(badvpn-tuntest
	tuntest.c
)

target_link_libraries(badvpn-tuntest badvpn-tun2socks system flow tuntap lwip socksclient udpgw_client)