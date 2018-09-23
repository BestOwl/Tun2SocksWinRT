/**
* @file SockTun.c
* @author MicroHao <microhaohao@gmail.com>
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

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // !WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdlib.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")

#include <base/BLog.h>

#include <tun2socks/socktun.h>

void report_error(SockTun *obj)
{
	DEBUGERROR(&obj->d_err, obj->handler_error(obj->handler_error_user));
}

static void recv_olap_handler(SockTun *obj, int event, DWORD bytes)
{
	DebugObject_Access(&obj->d_obj);
	ASSERT(obj->output_packet)
	ASSERT(event == BREACTOR_IOCP_EVENT_SUCCEEDED || event == BREACTOR_IOCP_EVENT_FAILED)

	// set no output packet
	obj->output_packet = NULL;

	if (event == BREACTOR_IOCP_EVENT_FAILED) {
		BLog(BLOG_ERROR, "read operation failed");
		report_error(obj);
		return;
	}

	ASSERT(bytes >= 0)
	ASSERT(bytes <= obj->mtu)

	// done
	PacketRecvInterface_Done(&obj->output, bytes);
}

void output_handler_recv(SockTun *obj, uint8_t *data)
{
	DebugObject_Access(&obj->d_obj);
	DebugError_AssertNoError(&obj->d_err);
	ASSERT(data)
	ASSERT(!obj->output_packet)

	memset(&obj->recv_olap.olap, 0, sizeof(obj->recv_olap.olap));
	memset(&obj->wsa_buf, 0, sizeof(obj->wsa_buf));

	// read
	obj->wsa_buf.buf = data;
	obj->wsa_buf.len = obj->mtu;
	BOOL res = WSARecvFrom(obj->device, &obj->wsa_buf, 
		1, &obj->wsa_bytes_recv, 
		&obj->wsa_flags, (SOCKADDR *) &obj->output_addr, 
		&obj->output_addr_size, &obj->recv_olap.olap, 
		NULL);
	if (res != 0 && GetLastError() != ERROR_IO_PENDING) {
		BLog(BLOG_ERROR, "ReadFile failed (%u)", GetLastError());
		report_error(obj);
		return;
	}

	obj->output_packet = obj->wsa_buf.buf;
}

int SockTun_Init(SockTun *obj, BReactor *reactor, char *tun_service_name, int mtu, SockTun_handler_error handler_error, void *handler_error_user)
{
	// Init arguments
	obj->mtu = mtu;
	obj->reactor = reactor;
	obj->handler_error = handler_error;
	obj->handler_error_user = handler_error_user;

	WSADATA wsaData;
	int iResult;

	SOCKET SSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		BLog(BLOG_ERROR, "WSAStartup failed with error: %d\n", iResult);
		return 0;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, (PCSTR)tun_service_name, &hints, &result);
	if (iResult != 0) {
		BLog(BLOG_ERROR, "getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 0;
	}

	// Create a SOCKET for server
	SSocket = WSASocket(result->ai_family, result->ai_socktype, result->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (SSocket == INVALID_SOCKET) {
		BLog(BLOG_ERROR, "Socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 0;
	}

	// Setup the UDP listening socket
	iResult = bind(SSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		BLog(BLOG_ERROR, "Bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(SSocket);
		WSACleanup();
		return 0;
	}

	// Init tunnel output address
	obj->output_addr_size = sizeof(obj->output_addr);

	freeaddrinfo(result);

	BLog(BLOG_INFO, "UDP socket binded to %s", tun_service_name);
	
	// Associate socket with IOCP
	if (!CreateIoCompletionPort((HANDLE)SSocket, BReactor_GetIOCPHandle(reactor), 0, 0)) {
		BLog(BLOG_ERROR, "CreateIoCompletionPort failed");
		CloseHandle((HANDLE)SSocket);
		return 0;
	}

	obj->device = SSocket;

	// init send olap
	BReactorIOCPOverlapped_Init(&obj->send_olap, reactor, obj, NULL);

	// init recv olap
	BReactorIOCPOverlapped_Init(&obj->recv_olap, obj->reactor, obj, (BReactorIOCPOverlapped_handler)recv_olap_handler);

	// init output
	PacketRecvInterface_Init(&obj->output, obj->mtu, (PacketRecvInterface_handler_recv)output_handler_recv, obj, BReactor_PendingGroup(obj->reactor));

	// set no output packet
	obj->output_packet = NULL;

	DebugError_Init(&obj->d_err, BReactor_PendingGroup(obj->reactor));
	DebugObject_Init(&obj->d_obj);

	return 1;
}

void SockTun_Send(SockTun *obj, uint8_t *data, int data_len) 
{
	DebugObject_Access(&obj->d_obj);
	DebugError_AssertNoError(&obj->d_err);
	ASSERT(data_len >= 0)
	ASSERT(data_len <= obj->mtu)

	// ignore frames without an Ethernet header, or we get errors in WriteFile
	if (data_len < 14) {
		return;
	}

	memset(&obj->send_olap.olap, 0, sizeof(obj->send_olap.olap));
	memset(&obj->wsa_buf, 0, sizeof(obj->wsa_buf));

	// write
	obj->wsa_buf.buf = data;
	obj->wsa_buf.len = data_len;
	BOOL res = WSASendTo(
		obj->device, &obj->wsa_buf,
		1, &obj->wsa_bytes_sent,
		obj->wsa_flags, (SOCKADDR *) &obj->output_addr,
		obj->output_addr_size, &obj->send_olap.olap,
		NULL);
	int err = GetLastError();
	if (res != 0 && GetLastError() != ERROR_IO_PENDING) {
		BLog(BLOG_ERROR, "WriteFile failed (%u)", GetLastError());
		return;
	}

	// wait
	int succeeded;
	DWORD bytes;
	BReactorIOCPOverlapped_Wait(&obj->send_olap, &succeeded, &bytes);

	if (!succeeded) {
		BLog(BLOG_ERROR, "write operation failed");
	}
	else {
		ASSERT(bytes >= 0)
		ASSERT(bytes <= data_len)

		if (bytes < data_len) {
			BLog(BLOG_ERROR, "write operation didn't write everything");
		}
	}
}

int SockTun_GetMTU(SockTun *obj)
{
	DebugObject_Access(&obj->d_obj);
	return obj->mtu;
}

PacketRecvInterface * SockTun_GetOutput(SockTun *obj)
{
	DebugObject_Access(&obj->d_obj);

	return &obj->output;
}

int winsock_init(char* tun_service_name, int mtu)
{
	WSADATA wsaData;
	int iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	int iSendResult;
	char recvbuf[512];
	int recvbuflen = 512;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		BLog(BLOG_ERROR, "WSAStartup failed with error: %d\n", iResult);
		return 0;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, (PCSTR)tun_service_name, &hints, &result);
	if (iResult != 0) {
		BLog(BLOG_ERROR, "getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 0;
	}

	// Create a SOCKET for connecting to server
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		BLog(BLOG_ERROR, "Socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 0;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		BLog(BLOG_ERROR, "Bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 0;
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("Listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 0;
	}

	BLog(BLOG_INFO, "Socket listening on %s", tun_service_name);

	// Associate socket with IOCP
	/*if (!CreateIoCompletionPort((HANDLE)ListenSocket, BReactor_GetIOCPHandle(ss), 0, 0)) {
		BLog(BLOG_ERROR, "CreateIoCompletionPort failed");
		CloseHandle((HANDLE)ListenSocket);
		return 0;
	}*/

	// init send olap
	//BReactorIOCPOverlapped_Init(send_olap, ss, o, NULL);

	// init recv olap
	//BReactorIOCPOverlapped_Init(&o->recv_olap, o->reactor, o, (BReactorIOCPOverlapped_handler)recv_olap_handler);


	// Accept a client socket
	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	// No longer need server socket
	closesocket(ListenSocket);

	// Receive until the peer shuts down the connection
	do {

		iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0) {
			printf("Bytes received: %d\n", iResult);

			// Echo the buffer back to the sender
			iSendResult = send(ClientSocket, recvbuf, iResult, 0);
			if (iSendResult == SOCKET_ERROR) {
				printf("send failed with error: %d\n", WSAGetLastError());
				closesocket(ClientSocket);
				WSACleanup();
				return 1;
			}
			printf("Bytes sent: %d\n", iSendResult);
		}
		else if (iResult == 0)
			printf("Connection closing...\n");
		else {
			printf("recv failed with error: %d\n", WSAGetLastError());
			closesocket(ClientSocket);
			WSACleanup();
			return 1;
		}

	} while (iResult > 0);

	// shutdown the connection since we're done
	iResult = shutdown(ClientSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ClientSocket);
		WSACleanup();
		return 1;
	}

	// cleanup
	closesocket(ClientSocket);
	WSACleanup();

	return 0;

}