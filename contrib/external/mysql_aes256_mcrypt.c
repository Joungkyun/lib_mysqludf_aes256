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
#include <mcrypt.h>
#include <mysql.h>

#include <mysql_aes256_config.h>
#include <mysql_aes256.h>

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
	DEBUG_SUB_FUNCTION_IN;

	if ( aes->handle != null )
		return true;

	aes->handle = mcrypt_module_open (MCRYPT_RIJNDAEL_128, NULL, MCRYPT_ECB, NULL);
	if ( aes->handle == MCRYPT_FAILED ) {
		sprintf (
			msg,
			"Mcrypt module open failed (udf: %s %s:%d)\n",
			MY_AES256_DEBUGINFO
		);
		return false;
	}

	aes->keysize   = mcrypt_enc_get_key_size (aes->handle);   // 32
	aes->blocksize = mcrypt_enc_get_block_size (aes->handle); // 16

	DEBUG_SUB_FUNCTION_OUT;
	return true;
}

void aes256_close_api (AES256_DATA * aes) {
	DEBUG_SUB_FUNCTION_IN;
	mcrypt_module_close (aes->handle);
	aes->handle = null;
	DEBUG_SUB_FUNCTION_OUT;
}

my_bool aes256_encrypt_api (AES256_DATA * aes) {
	int r;
	int blocks;
	int padlen;

	DEBUG_SUB_FUNCTION_IN;

	if ( aes->handle == null ) {
		fprintf (
			stderr,
			"Mcrypt handle is not initialize. (udf: %s %s:%d)\n",
			MY_AES256_DEBUGINFO
		);
		DEBUG_SUB_FUNCTION_OUT;
		return false;
	}

	if ( aes->datalen < 1 || aes->keylen < 1 ) {
		fprintf (
			stderr,
			"The data or key is missing. (udf: %s %s:%d)\n",
			MY_AES256_DEBUGINFO
		);
		DEBUG_SUB_FUNCTION_OUT;
		return false;
	}

	r = mcrypt_generic_init (aes->handle, aes->key, aes->keysize, NULL);
	if ( r < 0 ) {
		aes256_close_api (aes);
		fprintf (
			stderr,
			"%s (udf: %s %s:%d)\n",
			mcrypt_strerror (r), MY_AES256_DEBUGINFO
		);
		DEBUG_SUB_FUNCTION_OUT;
		return false;
	}

#ifdef MY_AES256_DEBUG
	fprintf (stderr, "  - data    : %s (udf: %s:%d)\n", aes->data, MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - datalen : %u (%zd) (udf: %s:%d)\n", aes->datalen, strlen ((char *) aes->data), MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - key     : %s (udf: %s:%d)\n", aes->key, MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - keylen  : %u (udf: %s:%d)\n", aes->keylen, MY_AES256_SDEBUGINFO);
#endif

	blocks = aes->blocksize * ((int) (aes->datalen / aes->blocksize) + 1);
	blocks = sizeof (char) * (blocks);

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

	memset (aes->buffer, 0, blocks + 1);

	if ( aes->datalen > blocks )
		aes->datalen = blocks - 1;

	memcpy (aes->buffer, aes->data, aes->datalen);
	padlen = blocks - aes->datalen;
	// padding
	memset (aes->buffer + aes->datalen, padlen, ((int) padlen));

#ifdef MY_AES256_DEBUG
	fprintf (stderr, "  - blocks  : %d (udf: %s:%d)\n", blocks, MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - buf     : %s (udf: %s:%d)\n", aes->buffer, MY_AES256_SDEBUGINFO);
	int i;
	fprintf (stderr, "    ");
	for ( i=0; i<blocks; i++ ) {
		fprintf (stderr, "%d ", aes->buffer[i]);
	}
	fprintf (stderr, "(udf: %s:%d)\n", MY_AES256_SDEBUGINFO);
#endif

	r = mcrypt_generic (aes->handle, aes->buffer, blocks);
	if ( r ) {
		fprintf (
			stderr,
			"%s (udf: %s %s:%d)\n",
			mcrypt_strerror (r), MY_AES256_DEBUGINFO
		);
		DEBUG_SUB_FUNCTION_OUT;
		return r;
	}

#ifdef MY_AES256_DEBUG
	fprintf (stderr, "  - buf     : %s (udf: %s:%d)\n", aes->buffer, MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - buflen  : %u (%zd) (udf: %s:%d)\n", blocks, strlen ((char *) aes->buffer), MY_AES256_SDEBUGINFO);

	fprintf (stderr, "    ");
	for ( i=0; i<blocks; i++ ) {
		fprintf (stderr, "%d ", aes->buffer[i]);
	}
	fprintf (stderr, "(udf: %s:%d)\n", MY_AES256_SDEBUGINFO);
#endif

	aes->datalen = blocks;

	mcrypt_generic_deinit (aes->handle);
	aes256_close_api (aes);

	DEBUG_SUB_FUNCTION_OUT;
	return true;
}

my_bool aes256_decrypt_api (AES256_DATA * aes) {
	int r;
	int blocks;
	char last;

	DEBUG_SUB_FUNCTION_IN;

	if ( aes->handle == null ) {
		fprintf (
			stderr,
			"Mcrypt handle is not initialize. (udf: %s %s:%d)\n",
			MY_AES256_DEBUGINFO
		);
		DEBUG_SUB_FUNCTION_OUT;
		return false;
	}

	if ( aes->datalen < 1 || aes->keylen < 1 ) {
		fprintf (
			stderr,
			"The data or key is missing. (udf: %s %s:%d)\n",
			MY_AES256_DEBUGINFO
		);
		DEBUG_SUB_FUNCTION_OUT;
		return false;
	}

	r = mcrypt_generic_init (aes->handle, aes->key, aes->keysize, NULL);
	if ( r < 0 ) {
		fprintf (
			stderr,
			"%s (udf: %s %s:%d)\n",
			mcrypt_strerror (r), MY_AES256_DEBUGINFO
		);
		aes256_close_api (aes);
		DEBUG_SUB_FUNCTION_OUT;
		return false;
	}

#ifdef MY_AES256_DEBUG
	fprintf (stderr, "  - data    : %s (udf: %s:%d)\n", aes->data, MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - datalen : %u (%zd) (udf: %s:%d)\n", aes->datalen, strlen ((char *) aes->data), MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - key     : %s (udf: %s:%d)\n", aes->key, MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - keylen  : %u (udf: %s:%d)\n", aes->keylen, MY_AES256_SDEBUGINFO);
#endif

	blocks = sizeof (char) * (aes->datalen + 1);
	aes->buffer = (unsigned char *) malloc (blocks);
	memset (aes->buffer, 0, blocks);
	memcpy (aes->buffer, aes->data, aes->datalen);

#ifdef MY_AES256_DEBUG
	fprintf (stderr, "  - blocks  : %d (udf: %s:%d)\n", blocks, MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - buf     : %s (udf: %s:%d)\n", aes->buffer, MY_AES256_SDEBUGINFO);
	int i;
	fprintf (stderr, "    ");
	for ( i=0; i<blocks; i++ ) {
		fprintf (stderr, "%d ", aes->buffer[i]);
	}
	fprintf (stderr, "(udf: %s:%d)\n", MY_AES256_SDEBUGINFO);
#endif

	r = mdecrypt_generic (aes->handle, aes->buffer, aes->datalen);
	mcrypt_generic_deinit (aes->handle);
	aes256_close_api (aes);

	if ( r ) {
		fprintf (
			stderr,
			"%s (udf: %s %s:%d)\n",
			mcrypt_strerror (r), MY_AES256_DEBUGINFO
		);
		DEBUG_SUB_FUNCTION_OUT;
		return false;
	}

	last = aes->buffer[strlen ((char *) aes->buffer) - 1];
	if ( last > aes->blocksize ) {
		fprintf (
			stderr,
			"Wrong blcoksize matching (udf: %s %s:%d)\n",
			MY_AES256_DEBUGINFO
		);
		DEBUG_SUB_FUNCTION_OUT;
		return false;
	}

#ifdef MY_AES256_DEBUG
	fprintf (stderr, "  - buf     : %s (udf: %s:%d)\n", aes->buffer, MY_AES256_SDEBUGINFO);
	fprintf (stderr, "  - buflen  : %u (%zd) (udf: %s:%d)\n", blocks, strlen ((char *) aes->buffer), MY_AES256_SDEBUGINFO);

	fprintf (stderr, "    ");
	for ( i=0; i<blocks; i++ ) {
		fprintf (stderr, "%d ", aes->buffer[i]);
	}
	fprintf (stderr, "(udf: %s:%d)\n", MY_AES256_SDEBUGINFO);
#endif

	aes->datalen = strlen ((char *) aes->buffer) - last;
	aes->buffer[aes->datalen] = 0;

	DEBUG_SUB_FUNCTION_OUT;
	return true;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
