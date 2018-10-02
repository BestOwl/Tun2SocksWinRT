/**
* @file cryptoman.c
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

#include <system/BReactor.h>
#include <base/BLog.h>
#include <openssl/rand.h>

#include "cryptoman.h"

int cryptoman_Init(char  *crypto_method_name, char *password)
{
	OpenSSL_add_all_algorithms();

	ss_crypto_info.cipher = EVP_get_cipherbyname(crypto_method_name);
	if (!ss_crypto_info.cipher)
	{
		BLog(BLOG_ERROR, "Unsupoorted crypto method %s", crypto_method_name);
		return 0;
	}
	
	ss_crypto_info.dgst = EVP_get_digestbyname("md5");
	if (!ss_crypto_info.dgst)
	{ 
		BLog(BLOG_ERROR, "EVP_get_digestbyname failed"); 
		return 0;
	}

	ss_crypto_info.key_len = EVP_BytesToKey(ss_crypto_info.cipher, ss_crypto_info.dgst, NULL, password, strlen(password), 1, ss_crypto_info.key, NULL);
	if (!ss_crypto_info.key_len)
	{
		BLog(BLOG_ERROR, "EVP_BytesToKey failed");
		return 0;
	}
	
	// TO-DO: some cipher iv may less than 16
	ss_crypto_info.iv_size = EVP_MAX_IV_LENGTH;

	ss_crypto_info.password = password;

	BLog(BLOG_INFO, "Using method: %s", crypto_method_name);
	return 1;
}

int random_iv(char *iv, int size)
{
	return RAND_bytes(iv, size);
}

int encryptor_Init(EVP_CIPHER_CTX *octx, const char *iv)
{
	// initialise the context 
	if (1 != EVP_EncryptInit_ex(octx, ss_crypto_info.cipher, NULL, ss_crypto_info.key, iv))
	{
		BLog(BLOG_DEBUG, "EVP_EncryptInit_ex failed");
		return 0;
	}

	if (1 != EVP_CIPHER_CTX_set_key_length(octx, ss_crypto_info.key_len))
	{
		BLog(BLOG_ERROR, "EVP_CIPHER_CTX_set_key_length failed");
		return 0;
	}

	// set no padding
	EVP_CIPHER_CTX_set_padding(octx, 0);

	return 1;
}

int decryptor_Init(EVP_CIPHER_CTX *octx, const char *iv)
{
	// initialise the context 
	if (1 != EVP_DecryptInit_ex(octx, ss_crypto_info.cipher, NULL, ss_crypto_info.key, iv))
	{
		BLog(BLOG_DEBUG, "EVP_DecryptInit_ex failed");
		return 0;
	}

	if (1 != EVP_CIPHER_CTX_set_key_length(octx, ss_crypto_info.key_len))
	{
		BLog(BLOG_ERROR, "EVP_CIPHER_CTX_set_key_length failed");
		return 0;
	}

	// set no padding
	EVP_CIPHER_CTX_set_padding(octx, 0);

	return 1;
}

int encrypt(EVP_CIPHER_CTX *ctx, uint8_t *buf, int buf_len, uint8_t *ciphertext)
{
	int ciphertext_len;

	// Provide the message to be encrypted, and obtain the encrypted output.
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buf, buf_len))
	{
		BLog(BLOG_ERROR, "EVP_EncryptUpdate failed, could not encrypt buffer");
	}

	return ciphertext_len;
}

int decrypt(EVP_CIPHER_CTX *ctx, uint8_t *buf, int buf_len, uint8_t *plaintext)
{
	int plaintext_len;

	// Provide the message to be decrypted, and obtain the plaintext output.
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, buf, buf_len))
	{
		BLog(BLOG_ERROR, "EVP_DecryptUpdate failed, could not decrypt buffer");
	}

	return plaintext_len;
}

void cryptor_free(EVP_CIPHER_CTX *ctx)
{
	EVP_CIPHER_CTX_free(ctx);
}
