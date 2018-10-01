badvpn_add_library(socksclient "system;flow;flowextra" "" 
	"BSocksClient.c"
)

find_package(OpenSSL REQUIRED)
target_link_libraries(socksclient OpenSSL::Crypto)