#include <stdlib.h>
#include <stdio.h>
#include <tun2socks/tun2socks.h>

int main(int argc, char **argv)
{
	/*char* args[9];
	args[0] = "";
	args[1] = "--tundev";
	args[2] = "tap0901:Tun2socks:10.0.0.1:10.0.0.0:255.255.255.0";
	args[3] = "--netif-ipaddr";
	args[4] = "10.0.0.2";
	args[5] = "--netif-netmask";
	args[6] = "255.255.255.0";
	args[7] = "--socks-server-addr";
	args[8] = "127.0.0.1:1080";
	args[9] = "--loglevel";
	args[10] = "debug";

	main_t(11, args);*/

	tun2socks_Init("60000", "172.19.0.1", "255.255.255.255", 1500, "192.168.1.107:60000", "aes-256-cfb", "SSTest");
}