/**
* @file tun2socks.h
* @author MicroHao <microhaohao@gmail.com>
*
* Windows Runtime wrapper for tun2socks.
*
* @section LICENSE
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. Neither the name of the author nor the
*    names of its contributors may be used to endorse or promote products
*    derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#pragma once

extern "C" {
#include <tun2socks/tun2socks.h>
void tun2socks_Init(const char *tun_service_name, const char  *vlan_addr, const char *vlan_netmask, int mtu, const char *socks_server_addr, const char *crypto_method, const char *socks_server_password);
}

namespace Tun2SocksWinRT 
{
	public ref class Tun2Socks sealed
	{
		public:
			void Init(Platform::String^ tunServiceName, Platform::String^ vlanAddr, Platform::String^ vlanNetmask, int mtu, Platform::String^ socksServerAddr, Platform::String^ cryptoMethod, Platform::String^ socksServerPassword);

		/*private:
			static void stdlog(int channel, int level, const char *msg);*/
	};
}