add_library(Tun2SocksWinRT SHARED
	tun2socks.cpp
	tun2socks.h
)

set_target_properties(Tun2SocksWinRT PROPERTIES VS_WINRT_COMPONENT TRUE)
set_target_properties(Tun2SocksWinRT PROPERTIES VS_GLOBAL_ROOTNAMESPACE "Tun2SocksWinRT")

target_link_libraries(Tun2SocksWinRT system flow lwip socksclient udpgw_client badvpn-tun2socks)

add_definitions(-DBADVPN_USE_WINSOCK_AS_TUN_DEVICE)