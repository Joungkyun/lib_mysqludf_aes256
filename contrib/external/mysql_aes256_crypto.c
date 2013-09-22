/*
 *                       Written by JoungKyun.Kim
 *            Copyright (c) 2013 JoungKyun.Kim <http://oops.org>
 *
 * -----------------------------------------------------------------------------
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 * 
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 * 
 *     * Neither the name of JoungKyun.Kim nor the url of http[s]://[*.]oops.org
 *       nor the names of their contributors may be used to endorse or
 *       promote products derived from this software without specific prior
 *       written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * -----------------------------------------------------------------------------
 * This file is part of lib_mysqludf_aes267
 *
 * $Id$
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <mysql.h>

#include <mysql_aes256_config.h>
#include <mysql_aes256.h>

#ifdef FORCE_CRYPTO
	#ifdef HAVE_MCRYPT_H
		#undef HAVE_MCRYPT_H
	#endif
#endif

typedef struct aes256_data {
	unsigned char * data;
	int datalen;
	unsigned char * key;
	int keylen;
	unsigned char * iv;
	int ivlen;
	int keysize;
	int blocksize;
	int ivsize;
	unsigned char * buffer;
	void * handle;
} AES256_DATA;

my_bool aes256_init_api (AES256_DATA * aes, char *msg) {
	EVP_CIPHER_CTX *e;
	int i;
	int nrounds = 5;
	unsigned char iv[32], ckey[32];

	DEBUG_SUB_FUNCTION_IN;

	if ( aes->handle != null )
		return true;

	/*
	 * Gen key & IV for AES 256 ECB mode. A SHA1 digest is used to hash
	 * the supplied key material. nrounds is the number of times the
	 * we hash the material. More rounds are more secure but
	 * slower.
	 */
	i = EVP_BytesToKey (
			EVP_aes_256_ecb (),
			EVP_sha1 (), NULL,
			aes->key,
			aes->keylen,
			nrounds,
			ckey,
			iv
	);

	if ( i != 32 ) {
		sprintf (msg, "Key size is %d bits - should be 256 bits\n", i);
		sprintf (
			msg,
			"Key size is %d bits - should be 256 bits (udf: %s %s:%d)\n",
			i, MY_AES256_DEBUGINFO
		);
		DEBUG_SUB_FUNCTION_OUT;
		return false;
	}

	e = (EVP_CIPHER_CTX *) malloc (sizeof (EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init (e);

	aes->handle = (EVP_CIPHER_CTX *) e;
	aes->keysize   = 32;
	aes->blocksize = 16;

	DEBUG_SUB_FUNCTION_OUT;
	return true;
}

void aes256_close_api (AES256_DATA * aes) {
	DEBUG_SUB_FUNCTION_IN;
	EVP_CIPHER_CTX_cleanup (aes->handle);
	aes->handle = null;
	DEBUG_SUB_FUNCTION_OUT;
}

my_bool aes256_encrypt_api (AES256_DATA * aes) {
	int blocks;
	int length;

	DEBUG_SUB_FUNCTION_IN;

	if ( aes->handle == null ) {
		fprintf (
			stderr,
			"EVP Encrypt handle is not initialize. (udf: %s %s:%d)\n",
			MY_AES256_DEBUGINFO
		);
		DEBUG_SUB_FUNCTION_OUT;
		return false;
	}

	EVP_EncryptInit_ex (aes->handle, EVP_aes_256_ecb (), NULL, aes->key, NULL);
	blocks = sizeof (char) * aes->datalen * aes->blocksize;

#ifdef MY_AES256_DEBUG
	fprintf (stderr, "  - data    : %s (udf: %s:%d)\n", aes->data, MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - datalen : %u (%zd) (udf: %s:%d)\n", aes->datalen, strlen ((char *) aes->data), MY_AES256_SDEBUGINFO);
	int i;
	fprintf (stderr, "    ");
	for ( i=0; i<aes->datalen; i++ ) {
		fprintf (stderr, "%d ", aes->data[i]);
	}
	fprintf (stderr, "(udf: %s:%d)\n", MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - key     : %s (udf: %s:%d)\n", aes->key, MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - keylen  : %u (udf: %s:%d)\n", aes->keylen, MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - blocks  : %d (udf: %s:%d)\n", blocks, MY_AES256_SDEBUGINFO);
#endif

	aes->buffer = (unsigned char *) malloc (blocks + 1);
	if ( aes->buffer == null ) {
		fprintf (
			stderr,
			"Failed memory allocated (udf: %s %s:%d)\n",
			MY_AES256_DEBUGINFO
		);
		DEBUG_SUB_FUNCTION_OUT;
		return false;
	}
	memset (aes->buffer, 0, blocks);

	EVP_EncryptInit_ex (aes->handle, NULL, NULL, NULL, NULL);
	EVP_EncryptUpdate (aes->handle, aes->buffer, &blocks, aes->data, aes->datalen);
	EVP_EncryptFinal_ex(aes->handle, aes->buffer + blocks, &length);

#ifdef MY_AES256_DEBUG
	fprintf (stderr, "  - buf     : %s (udf: %s:%d)\n", aes->buffer, MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - buflen  : %u (%zd) (udf: %s:%d)\n", blocks, strlen ((char *) aes->buffer), MY_AES256_SDEBUGINFO);

	fprintf (stderr, "    ");
	for ( i=0; i<blocks; i++ ) {
		fprintf (stderr, "%d ", aes->buffer[i]);
	}
	fprintf (stderr, "(udf: %s:%d)\n", MY_AES256_SDEBUGINFO);
#endif

	aes->datalen = blocks + length;
	DEBUG_SUB_FUNCTION_OUT;
	return true;
}

my_bool aes256_decrypt_api (AES256_DATA * aes) {
	int blocks;
	int length;

	DEBUG_SUB_FUNCTION_IN;

	EVP_DecryptInit_ex (aes->handle, EVP_aes_256_ecb (), NULL, aes->key, NULL);
	blocks = sizeof (char) * aes->datalen;

	aes->buffer = (unsigned char *) malloc (blocks + 1);
	if ( aes->buffer == null ) {
		fprintf (
			stderr,
			"Failed memory allocated (udf: %s %s:%d)\n",
			MY_AES256_DEBUGINFO
		);
		DEBUG_SUB_FUNCTION_OUT;
		return false;
	}
	memset (aes->buffer, 0, blocks);

	EVP_DecryptInit_ex(aes->handle, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(aes->handle, aes->buffer, &blocks, aes->data, aes->datalen);
	EVP_DecryptFinal_ex(aes->handle, aes->buffer + blocks, &length);

	aes->datalen = blocks + length;
	aes->buffer[aes->datalen] = 0;

	DEBUG_SUB_FUNCTION_OUT;
	return true;
}
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
