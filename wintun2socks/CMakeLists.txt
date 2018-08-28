set (WINTUN2SOCKS_SOURCE
	dllmain.cpp
	lwipcfg_msvc.h
	pch.cpp
	pch.h
	Random.cpp
	Random.h
	sio.c
	targetver.h
	TcpSocket.cpp
	TcpSocket.h
	Wintun.cpp
	Wintun.h
	sys_arch.c
)
badvpn_add_shared_library(wintun2socks "lwip" "" "${WINTUN2SOCKS_SOURCE}" SHARED)
set_target_properties(wintun2socks PROPERTIES VS_WINRT_COMPONENT TRUE)

target_compile_options(wintun2socks PRIVATE "/TP") # compile with cpp
target_compile_options(wintun2socks PRIVATE "/EHsc") # use cpp exception
target_compile_options(wintun2socks PRIVATE "/Gz")

add_compile_options(/RTC1)