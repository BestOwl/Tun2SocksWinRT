/**
* @file tun2socks.cpp
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

#include <cvt/wstring>
#include <codecvt>
#include <base/BLog.c>
#include "tun2socks.h"

namespace Tun2SocksWinRT 
{
	void Tun2Socks::stdlog(int channel, int level, const char *msg)
	{
		fprintf(stdout, "%s(%s): %s\n", level_names[level], blog_global.channels[channel].name, msg);
	}

	void Tun2Socks::Init(Platform::String^ tunServiceName, Platform::String^ vlanAddr, Platform::String^ vlanNetmask, int mtu, Platform::String^ socksServerAddr, Platform::String^ socksServerPassword)
	{
		// Cast String to char*
		stdext::cvt::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		char* service_name = const_cast<char*>(converter.to_bytes(tunServiceName->Data()).c_str());
		char* vlan_addr = const_cast<char*>(converter.to_bytes(vlanAddr->Data()).c_str());
		char* vlan_netmask = const_cast<char*>(converter.to_bytes(vlanNetmask->Data()).c_str());
		char* socks_addr = const_cast<char*>(converter.to_bytes(socksServerAddr->Data()).c_str());
		char* socks_password = const_cast<char*>(converter.to_bytes(socksServerPassword->Data()).c_str());

		tun2socks_Init(service_name, vlan_addr, vlan_netmask, mtu, socks_addr, socks_password, (_BLog_log_func) stdlog);
	}
}


