/*
 *                       Written by JoungKyun.Kim
 *            Copyright (c) 2013 JoungKyun.Kim <http://oops.org>
 *
 * -----------------------------------------------------------------------------
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2.1 of the License, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * -----------------------------------------------------------------------------
 * This file is part of lib_mysqludf_aes267
 *
 * $Id$
 */

#include <mysql_version.h>

#ifdef STANDARD
	/* STANDARD is defined, don't use any mysql functions */
	#include <stdlib.h>
	#include <stdio.h>
	#include <string.h>
	#ifdef __WIN__
		typedef unsigned __int64 ulonglong;	/* Microsofts 64 bit types */
		typedef __int64 longlong;
	#else
		typedef unsigned long long ulonglong;
		typedef long long longlong;
	#endif /*__WIN__*/
#else
	#if MYSQL_VERSION_ID < 100100
		#define HAVE_LOG2 // for mariadb < 10.1
	#endif
	#include <my_global.h>
	#include <my_sys.h>
	#if defined(MYSQL_SERVER)
		#include <m_string.h>		/* To get strmov() */
	#else
		/* when compiled as standalone */
		#include <string.h>
		#define strmov(a,b) stpcpy(a,b)
		#define bzero(a,b) memset(a,0,b)
	#endif
#endif
#include <mysql.h>
#include <ctype.h>

static pthread_mutex_t LOCK_hostname;

#ifdef __cplusplus
extern "C" {
#endif

#include <mysql_aes256_config.h>
#include <mysql_aes256.h>
#include <my_aes.h>

#ifdef HAVE_DLOPEN

#define AES256_BLOCK_SIZE 16	/* Block size in bytes */

/* Info */
EXPORT_API my_bool lib_mysqludf_aes256_info_init (
	UDF_INIT * initid, UDF_ARGS * args, char * message
) {
	DEBUG_FUNCTION_IN;

	if ( args->arg_count != 0 ) {
		strcpy (
			message,
			"No arguments allowed (udf: lib_mysqludf_json_info)"
		);
		DEBUG_FUNCTION_OUT;
		return false;
	}

	DEBUG_FUNCTION_OUT;
	return true;
}

EXPORT_API void lib_mysqludf_aes256_info_deinit (UDF_INIT * initid) {
	DEBUG_FUNCTION_IN;
	DEBUG_FUNCTION_OUT;
}

EXPORT_API char * lib_mysqludf_aes256_info (
	UDF_INIT * initid, UDF_ARGS * args, char * result,
	unsigned long * length, char * is_null, char * error
) {
	DEBUG_FUNCTION_IN;
	strcpy (result, VERSION);
	*length = strlen (VERSION);
	DEBUG_FUNCTION_OUT;
	return result;
}

/*
 * Encrypt
 *
 * Usage AES256_ENCRYPT(PLAINTEXT, KEY)
 *   PLAINTEXT - 암호화할 원본 문자열
 *   KEY       - 암호화시 사용할 키
 *               키 길이가 128bit(16byte)일 경우 AES-128로 암호화 되고,
 *               256bit(32byte)일 경우 AES-256으로 암호화 된다.
 */
EXPORT_API my_bool aes256_encrypt_init (UDF_INIT * initid, UDF_ARGS * args, char * message) {
	int i;
	DEBUG_FUNCTION_IN;

	if ( args->arg_count != 2 ) {
		sprintf (
			message,
			"\n%s requires two arguments (udf: %s)\n",
			__FUNCTION__, __FUNCTION__
		);
		DEBUG_FUNCTION_OUT;
		return false;
	}

	for ( i=0; i<2; i++ ) {
		if ( args->arg_type[i] != STRING_RESULT ) {
			sprintf (
				message,
				"%dst argument is must string (udf: %s)\n",
				i + 1, __FUNCTION__
			);
			DEBUG_FUNCTION_OUT;
			return false;
		}
	}

	initid->maybe_null = 1;
	initid->max_length = my_aes256_get_size (args->lengths[0]);

	if ( (initid->ptr = malloc (sizeof (char) * initid->max_length)) == null ) {
		sprintf (
			message, 
			"Failed Memory allocated (udf: %s)\n",
			__FUNCTION__
		);
		DEBUG_FUNCTION_OUT;
		return false;
	}
	memset (initid->ptr, 0, initid->max_length);

	DEBUG_FUNCTION_OUT;
	return true;
}

EXPORT_API void aes256_encrypt_deinit (UDF_INIT *initid __attribute__((unused)))
{
	DEBUG_FUNCTION_IN;
	safe_free (initid->ptr);
	DEBUG_FUNCTION_OUT;
}

EXPORT_API char * aes256_encrypt (
		UDF_INIT * initid __attribute__((unused)), UDF_ARGS * args, char * result,
		unsigned long * length, char * null_value, char * error __attribute__((unused)))
{
	int len;

	DEBUG_FUNCTION_IN;

	*null_value = 0;

	len = my_aes256_encrypt (
		args->args[0], args->lengths[0],
		initid->ptr,
		args->args[1], args->lengths[1]
	);

	if ( length < 0 ) {
		*null_value = 1;
		DEBUG_FUNCTION_OUT;
		return null;
	}

	result = initid->ptr;
	*length = (unsigned int) len;

	DEBUG_FUNCTION_OUT;
	return result;
}

/*
 * Decrypt
 *
 * Usage AES256_DECRYPT(PLAINTEXT, KEY)
 *   CIPHERTEXT - 복호화할 CIPHERTEXT
 *   KEY        - 복호화시 사용할 키
 */

EXPORT_API my_bool aes256_decrypt_init (UDF_INIT * initid, UDF_ARGS * args, char * message)
{
	DEBUG_FUNCTION_IN;
	int i;

	if ( args->arg_count != 2 ) {
		sprintf (
			message,
			"\n%s requires two arguments (udf: %s)\n",
			__FUNCTION__, __FUNCTION__
		);
		return false;
	}

	// init function에서 args에 binary data를 받지 못하는 것 같다.
	for ( i=1; i<2; i++ ) {
		if ( ! args->args[i] || ! args->lengths[i] ) {
			sprintf (
				message,
				"%dst argument is missing (udf: %s)\n",
				i + 1, __FUNCTION__
			);

			fprintf (
				stderr,
				"  - %dst Argument:\n"
				"    - type   : %d\n"
				"    - data   : %s\n"
				"    - length : %ld\n",
				i + 1, args->arg_type[i], args->args[i], args->lengths[i]
			);

			DEBUG_FUNCTION_OUT;
			return false;
		}

		if ( args->arg_type[i] != STRING_RESULT ) {
			sprintf (
				message,
				"%dst argument is must string (udf: %s)\n",
				i + 1, __FUNCTION__
			);
			DEBUG_FUNCTION_OUT;
			return false;
		}
	}


	initid->maybe_null = 1;
	initid->max_length = my_aes256_get_size (args->lengths[0]);

	if ( (args->lengths[0] / AES256_BLOCK_SIZE) == 0 ) {
		sprintf (
			message,
			"CIPHERTEXT(%ld) is longer than AES BLOCKSIZE(%d) (udf: %s)",
			args->lengths[0], AES256_BLOCK_SIZE, __FUNCTION__
		);
		return false;
	}

	if ( (initid->ptr = malloc (sizeof (char) *  initid->max_length)) == null ) {
		sprintf (
			message, 
			"Failed Memory allocated (udf: %s)\n",
			__FUNCTION__
		);
		return false;
	}
	memset (initid->ptr, 0, initid->max_length);

	return true;
}

EXPORT_API void aes256_decrypt_deinit (UDF_INIT * initid __attribute__((unused)))
{
	DEBUG_FUNCTION_IN;
	safe_free (initid->ptr);
	DEBUG_FUNCTION_OUT;
}

EXPORT_API char * aes256_decrypt (
	UDF_INIT * initid __attribute__((unused)), UDF_ARGS * args, char * result,
	unsigned long * length, char * null_value, char * error __attribute__((unused))
) {
	int len;

	DEBUG_FUNCTION_IN;

	*null_value = 0;

	if ( ! args->args[0] || ! args->lengths[0] ) {
		fprintf (
			stderr,
			"  - 1st Argument:\n"
			"    + type   : %d\n"
			"    + data   : %s\n"
			"    + length : %ld\n",
			args->arg_type[0], args->args[0], args->lengths[0]
		);
	}

#ifdef MY_AES256_DEBUG
	fprintf (stderr, "  - data    : %s (udf: %s:%d)\n", args->args[0], __FILE__, __LINE__);
	fprintf (stderr, "  - datalen : %u (%zd) (udf: %s:%d)\n", args->lengths[0], strlen ((char *) args->args[0]), __FILE__, __LINE__);
	fprintf (stderr, "  - key     : %s (udf: %s:%d)\n", args->args[1], __FILE__, __LINE__);
	fprintf (stderr, "  - keylen  : %u (udf: %s:%d)\n", args->lengths[1], __FILE__, __LINE__);
#endif

	len = my_aes256_decrypt (
		args->args[0], args->lengths[0],
		initid->ptr,
		args->args[1], args->lengths[1]
	);

	if ( len < 0 ) {
		*null_value = 1;
		DEBUG_FUNCTION_OUT;
		return null;
	}
	
	result = initid->ptr;
	*length = (unsigned int) len;

	DEBUG_FUNCTION_OUT;
	return result;
}

#endif /* HAVE_DLOPEN */

#ifdef __cplusplus
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
