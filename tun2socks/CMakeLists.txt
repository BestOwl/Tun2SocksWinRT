add_library(badvpn-tun2socks
    tun2socks.c
    SocksUdpGwClient.c
	SockTun.c
	SockTun.h
)
target_link_libraries(badvpn-tun2socks system flow lwip socksclient udpgw_client)
if(BUILD_TUN2SOCKSWINRT)
	add_definitions(-DBADVPN_USE_WINSOCK_AS_TUN_DEVICE)
else()
	target_link_libraries(badvpn-tun2socks tuntap)
endif()
