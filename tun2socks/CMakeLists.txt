add_library(badvpn-tun2socks
    tun2socks.c
    SocksUdpGwClient.c
	SockTun.c
	SockTun.h
)
target_link_libraries(badvpn-tun2socks system flow tuntap lwip socksclient udpgw_client)

add_definitions(-DBADVPN_USE_WINSOCK_AS_TUN_DEVICE)
