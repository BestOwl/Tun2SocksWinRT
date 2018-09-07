/**
* @file SockTun.h
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

#include <misc/debug.h>
#include <misc/debugerror.h>
#include <base/DebugObject.h>
#include <system/BReactor.h>
#include <flow/PacketRecvInterface.h>

/**
* Handler called when an error occurs on the device.
* The object must be destroyed from the job context of this
* handler, and no further I/O may occur.
*
* @param user as in {@link BTap_Init}
*/
typedef void(*SockTun_handler_error) (void *used);

typedef struct {
	BReactor *reactor;
	SockTun_handler_error handler_error;
	void *handler_error_user;
	int mtu;
	PacketRecvInterface output;
	uint8_t *output_packet;

#ifdef BADVPN_USE_WINAPI
	SOCKET device;
	struct sockaddr_in output_addr;
	BReactorIOCPOverlapped send_olap;
	BReactorIOCPOverlapped recv_olap;

	int output_addr_size;
	WSABUF wsa_buf;
	DWORD wsa_flags;
	DWORD wsa_bytes_recv;
	DWORD wsa_bytes_sent;
#else
	int close_fd;
	int fd;
	BFileDescriptor bfd;
	int poll_events;
#endif

	DebugError d_err;
	DebugObject d_obj;
} SockTun;

/**
 * Initializes the sock tunnel device.
 * Setup a winsock server to recieve data from tunnel
 *
 * @param o the object
 * @param BReactor {@link BReactor} we live in
 * @param the service name or port to recieve tunnel data 
 * @param mtu of the tunnel
 * @param handler_error error handler function
 * @param handler_error_user value passed to error handler
 */
int SockTun_Init(SockTun *obj, BReactor *ss, char *tun_service_name, char *tun_output_service_name, int mtu, SockTun_handler_error handler_error, void *handler_error_user);

/**
* Sends a packet to the device.
* Any errors will be reported via a job.
*
* @param o the object
* @param data packet to send
* @param data_len length of packet. Must be >=0 and <=MTU, as reported by {@link BTap_GetMTU}.
*/
void SockTun_Send(SockTun *obj, uint8_t *data, int data_len);

/**
* Returns the device's maximum transmission unit (including any protocol headers).
*
* @param o the object
* @return device's MTU
*/
int SockTun_GetMTU(SockTun *o);

/**
* Returns a {@link PacketRecvInterface} for reading packets from the device.
* The MTU of the interface will be {@link BTap_GetMTU}.
*
* @param o the object
* @return output interface
*/
PacketRecvInterface * SockTun_GetOutput(SockTun *o);