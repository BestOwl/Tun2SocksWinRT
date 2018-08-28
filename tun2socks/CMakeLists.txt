add_library(badvpn-tun2socks
    tun2socks.c
    SocksUdpGwClient.c
)
target_link_libraries(badvpn-tun2socks system flow tuntap lwip socksclient udpgw_client)
