add_library(badvpn-tun2socks
    tun2socks.c
    SocksUdpGwClient.c
	SockTun.c
	SockTun.h
	cryptoman.c
	cryptoman.h
)

find_package(OpenSSL REQUIRED)
target_link_libraries(badvpn-tun2socks OpenSSL::Crypto system flow lwip socksclient udpgw_client)
