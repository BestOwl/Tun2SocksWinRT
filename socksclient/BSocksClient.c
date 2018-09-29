/**
 * @file BSocksClient.c
 * @author Ambroz Bizjak <ambrop7@gmail.com>
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

#include <string.h>

#include <misc/byteorder.h>
#include <misc/balloc.h>
#include <base/BLog.h>

#include <socksclient/BSocksClient.h>

#include <generated/blog_channel_BSocksClient.h>

#define STATE_CONNECTING 1
#define STATE_SENDING_HELLO 2
#define STATE_SENT_HELLO 3
#define STATE_SENDING_PASSWORD 10
#define STATE_SENT_PASSWORD 11
#define STATE_SENDING_REQUEST 4
#define STATE_SENT_REQUEST 5
#define STATE_RECEIVED_REPLY_HEADER 6
#define STATE_UP 7

static void report_error (BSocksClient *o, int error);
static void init_crypto_io(BSocksClient *o);
static void free_crypto_io(BSocksClient *o);
static void init_up_io (BSocksClient *o);
static void free_up_io (BSocksClient *o);
static int reserve_buffer (BSocksClient *o, bsize_t size);
static void connector_handler (BSocksClient* o, int is_error);
static void connection_handler (BSocksClient* o, int event);
static void build_header(BSocksClient *p);

void report_error (BSocksClient *o, int error)
{
    DEBUGERROR(&o->d_err, o->handler(o->user, error))
}

static void encrypt_handler(BSocksClient *o, uint8_t *data, int data_len)
{
	// allocate cipher buffer
	if (!(o->cipher_buffer = BAlloc(data_len * 2)))
	{
		BLog(BLOG_ERROR, "BAlloc failed");
		return;
	}

	size_t cipher_buf_len;
	size_t iv_size = 0;
	size_t en_header_size = 0;

	// IV and header only need in the first packet
	if (!o->first_packet_sent)
	{
		// generate and copy IV
		iv_size = o->ss_iv_len;
		random_iv(o->ss_iv, iv_size);
		memcpy(o->cipher_buffer, o->ss_iv, iv_size);

		// copy header
		en_header_size = encrypt(o->header_buffer, o->header_len, o->ss_iv, o->cipher_buffer + iv_size);

		o->first_packet_sent = 1;
	}

	cipher_buf_len = encrypt(data, data_len, o->ss_iv, o->cipher_buffer + iv_size + en_header_size);
	cipher_buf_len += iv_size += en_header_size;

	o->plain_len = data_len;

	StreamPassInterface_Sender_Send(&o->con.send.iface, o->cipher_buffer, cipher_buf_len);
}

static void decrypt_handler(BSocksClient *o, uint8_t *data, int data_len)
{
	// allocate recv buffer
	if (!(o->socks_recv_buf = BAlloc(data_len)))
	{
		BLog(BLOG_ERROR, "BAlloc failed");
		return;
	}

	o->decrypted_buf = data;

	// padding to receive
	StreamRecvInterface_Receiver_Recv(&o->con.recv.iface, o->socks_recv_buf, data_len);
}

static void init_crypto_io(BSocksClient *o)
{
	// init reading
	StreamRecvInterface_Init(&o->decrypt_if, decrypt_handler, o, BReactor_PendingGroup(o->reactor));

	// init sending
	StreamPassInterface_Init(&o->encrypt_if, encrypt_handler, o, BReactor_PendingGroup(o->reactor));
}

static void free_crypto_io(BSocksClient *o)
{
	// free sending
	StreamPassInterface_Free(&o->encrypt_if);

	//free reading
	StreamRecvInterface_Free(&o->decrypt_if);
}

static void up_handler_done(BSocksClient *o, int data_len) 
{
	StreamPassInterface_Done(&o->encrypt_if, o->plain_len);
	o->plain_len = 0;

	// free buffer
	BFree(o->cipher_buffer);
}

static void down_handler_done(BSocksClient *o, int data_len)
{
	size_t iv_size = 0;

	if (!o->first_packet_recved)
	{
		memcpy(o->ss_remote_iv, o->socks_recv_buf, o->ss_iv_len);
		iv_size = o->ss_iv_len;

		o->first_packet_recved = 1;
	}

	size_t len = decrypt(o->socks_recv_buf + iv_size, data_len - iv_size, o->ss_remote_iv, o->decrypted_buf);

	StreamRecvInterface_Done(&o->decrypt_if, len);

	// free buffer
	BFree(o->socks_recv_buf);
}

void init_up_io (BSocksClient *o)
{
    // init receiving
    BConnection_RecvAsync_Init(&o->con);
	StreamRecvInterface_Receiver_Init(&o->con.recv.iface, down_handler_done, o);
    
    // init sending
    BConnection_SendAsync_Init(&o->con);
	StreamPassInterface_Sender_Init(&o->con.send.iface, up_handler_done, o);
}

void free_up_io (BSocksClient *o)
{
    // free sending
    BConnection_SendAsync_Free(&o->con);
    
    // free receiving
    BConnection_RecvAsync_Free(&o->con);
}

int reserve_buffer (BSocksClient *o, bsize_t size)
{
    if (size.is_overflow) {
        BLog(BLOG_ERROR, "size overflow");
        return 0;
    }
    
    char *buffer = (char *)BRealloc(o->header_buffer, size.value);
    if (!buffer) {
        BLog(BLOG_ERROR, "BRealloc failed");
        return 0;
    }
    
    o->header_buffer = buffer;
    
    return 1;
}
void connector_handler (BSocksClient* o, int is_error)
{
    DebugObject_Access(&o->d_obj);
    ASSERT(o->state == STATE_CONNECTING)
    
    // check connection result
    if (is_error) {
        BLog(BLOG_ERROR, "connection failed");
        goto fail0;
    }
    
    // init connection
    if (!BConnection_Init(&o->con, BConnection_source_connector(&o->connector), o->reactor, o, (BConnection_handler)connection_handler)) {
        BLog(BLOG_ERROR, "BConnection_Init failed");
        goto fail0;
    }
    
    BLog(BLOG_DEBUG, "connected");

	o->first_packet_sent = 0;
	o->first_packet_recved = 0;

	// init buffer
	build_header(o);

	// init crypto io
	init_crypto_io(o);

	// init up I/O
	init_up_io(o);

	// set state
	o->state = STATE_UP;

	// call handler
	o->handler(o->user, BSOCKSCLIENT_EVENT_UP);
    
    return;
    
fail0:
    report_error(o, BSOCKSCLIENT_EVENT_ERROR);
    return;
}

void connection_handler (BSocksClient* o, int event)
{
    DebugObject_Access(&o->d_obj);
    ASSERT(o->state != STATE_CONNECTING)
    
    if (o->state == STATE_UP && event == BCONNECTION_EVENT_RECVCLOSED) {
        report_error(o, BSOCKSCLIENT_EVENT_ERROR_CLOSED);
        return;
    }
    
    report_error(o, BSOCKSCLIENT_EVENT_ERROR);
    return;
}

void build_header (BSocksClient *o)
{
    // allocate request buffer
    bsize_t size = bsize_fromsize(sizeof(struct socks_request_header));
    switch (o->dest_addr.type) {
        case BADDR_TYPE_IPV4: size = bsize_add(size, bsize_fromsize(sizeof(struct socks_addr_ipv4))); break;
        case BADDR_TYPE_IPV6: size = bsize_add(size, bsize_fromsize(sizeof(struct socks_addr_ipv6))); break;
    }
    if (!reserve_buffer(o, size)) {
        report_error(o, BSOCKSCLIENT_EVENT_ERROR);
        return;
    }
	o->header_len = size.value;
    
    // write request
    struct socks_request_header header;
    switch (o->dest_addr.type) {
        case BADDR_TYPE_IPV4: {
            header.atyp = hton8(SOCKS_ATYP_IPV4);
            struct socks_addr_ipv4 addr;
            addr.addr = o->dest_addr.ipv4.ip;
            addr.port = o->dest_addr.ipv4.port;
            memcpy(o->header_buffer + sizeof(header), &addr, sizeof(addr));
        } break;
        case BADDR_TYPE_IPV6: {
            header.atyp = hton8(SOCKS_ATYP_IPV6);
            struct socks_addr_ipv6 addr;
            memcpy(addr.addr, o->dest_addr.ipv6.ip, sizeof(o->dest_addr.ipv6.ip));
            addr.port = o->dest_addr.ipv6.port;
            memcpy(o->header_buffer + sizeof(header), &addr, sizeof(addr));
        } break;
        default:
            ASSERT(0);
    }
    memcpy(o->header_buffer, &header, sizeof(header));
}

int BSocksClient_Init (BSocksClient *o,
                       BAddr server_addr, const struct BSocksClient_auth_info *auth_info, size_t num_auth_info,
                       BAddr dest_addr, BSocksClient_handler handler, void *user, BReactor *reactor)
{
    ASSERT(!BAddr_IsInvalid(&server_addr))
    ASSERT(dest_addr.type == BADDR_TYPE_IPV4 || dest_addr.type == BADDR_TYPE_IPV6)
    
    // init arguments
    o->dest_addr = dest_addr;
    o->handler = handler;
    o->user = user;
    o->reactor = reactor;
    
    // set no buffer
    o->header_buffer = NULL;
    
    // init connector
    if (!BConnector_Init(&o->connector, server_addr, o->reactor, o, (BConnector_handler)connector_handler)) {
        BLog(BLOG_ERROR, "BConnector_Init failed");
        goto fail0;
    }

	// init iv buffer
	o->ss_iv_len = ss_crypto_info.iv_size;
	if (!(o->ss_iv = BAlloc(o->ss_iv_len)))
	{
		BLog(BLOG_ERROR, "BAlloc failed");
		return 0;
	}
	if (!(o->ss_remote_iv = BAlloc(o->ss_iv_len)))
	{
		BLog(BLOG_ERROR, "BAlloc failed");
		return 0;
	}
    
    // set state
    o->state = STATE_CONNECTING;
    
    DebugError_Init(&o->d_err, BReactor_PendingGroup(o->reactor));
    DebugObject_Init(&o->d_obj);
    return 1;
    
fail0:
    return 0;
}

void BSocksClient_Free (BSocksClient *o)
{
    DebugObject_Free(&o->d_obj);
    DebugError_Free(&o->d_err);
    
    if (o->state != STATE_CONNECTING) {
        if (o->state == STATE_UP) {
            // free up I/O
            free_up_io(o);
			free_crypto_io(o);
        } 
        
        // free connection
        BConnection_Free(&o->con);
    }
    
    // free connector
    BConnector_Free(&o->connector);
    
    // free buffer
    if (o->header_buffer) {
        BFree(o->header_buffer);
    }
	if (o->ss_iv)
	{
		BFree(o->ss_iv);
	}
	if (o->ss_remote_iv)
	{
		BFree(o->ss_remote_iv);
	}
}

StreamPassInterface * BSocksClient_GetSendInterface (BSocksClient *o)
{
    ASSERT(o->state == STATE_UP)
    DebugObject_Access(&o->d_obj);
    
    return &o->encrypt_if;
}

StreamRecvInterface * BSocksClient_GetRecvInterface (BSocksClient *o)
{
    ASSERT(o->state == STATE_UP)
    DebugObject_Access(&o->d_obj);
    
    return &o->decrypt_if;
}
