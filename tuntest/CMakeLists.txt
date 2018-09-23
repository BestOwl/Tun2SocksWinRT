add_executable(badvpn-tuntest
	tuntest.c
)

find_package(OpenSSL REQUIRED)
target_link_libraries(badvpn-tuntest badvpn-tun2socks OpenSSL::Crypto system flow lwip socksclient udpgw_client)
