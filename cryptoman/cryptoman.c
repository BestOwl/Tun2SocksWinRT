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

	if (!EVP_BytesToKey(ss_crypto_info.cipher, ss_crypto_info.dgst, NULL, password, strlen(password), 1, ss_crypto_info.key, NULL))
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

void handleErrors()
{
	ERR_print_errors_fp(stderr);
	abort();
}

int encrypt(uint8_t *buf, int buf_len, const char *iv, uint8_t *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
	{
		handleErrors();
	}

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (1 != EVP_EncryptInit_ex(ctx, ss_crypto_info.cipher, NULL, ss_crypto_info.key, iv))
	{
		handleErrors();
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, buf, buf_len))
	{
		handleErrors();
	}

	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
	{
		handleErrors();
	}

	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt(uint8_t *buf, int buf_len, const *iv, uint8_t *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
	{
		handleErrors();
	}

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (1 != EVP_DecryptInit_ex(ctx, ss_crypto_info.cipher, NULL, ss_crypto_info.key, iv))
	{
		handleErrors();
	}

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, buf, buf_len))
	{
		handleErrors();
	}

	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
	{
		handleErrors();
	}

	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}
