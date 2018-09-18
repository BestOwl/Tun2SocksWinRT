# BadVPN

## Introduction

This project is designed for UWP VPN Platform, the only working part is tun2socks, NCD and other features in BadVPN will not work.
And is only works on Windows 10, although the original project is cross-platform, if you want to use on other platform or other BadVPN features, please go to https://github.com/ambrop72/badvpn

### Tun2socks (or Tun2shadowsocks) network-layer proxifier

The tun2socks program "socksifes" TCP connections at the network layer.
It implements a TUN device or a WinSock server which accepts all incoming TCP connections (regardless of destination IP), and forwards the connections through a SOCKS or Shadowsocks server.
This allows you to forward all connections through SOCKS or Shadowsocks, without any need for application support.
It can be used, for example, to forward connections through a remote SSH server.

## Requirements

 * Windows 10

## License

The BSD 3-clause license as shown below applies to most of the code.

```
Copyright (c) 2009, Ambroz Bizjak <ambrop7@gmail.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of the author nor the
   names of its contributors may be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

List of third-party code included in the source:
- lwIP - A Lightweight TCP/IP stack. License: `lwip/COPYING`
