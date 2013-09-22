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


#ifndef MYSQL_AES256_h
#define MYSQL_AES256_h

#ifdef EXPORT_API
	#undef EXPORT_API
#endif

#if defined _WIN32 || defined __CYGWIN__
	#ifdef DLL_EXPORT
		#define EXPORT_API __declspec(dllexport)
	#else
		#define EXPORT_API __declspec(dllimport)
	#endif
#else
	#if HAVE_VISIBILITY
		#define EXPORT_API __attribute__ ((visibility("default")))
	#else
		#define EXPORT_API
	#endif
#endif

#ifdef true
	#undef true
#endif

#ifndef false
	#undef false
#endif

#define true 0
#define false 1

#ifndef null
	#define null NULL
#endif

#ifndef safe_free
	#define safe_free(x) if ((x) != NULL) { free(x); x=NULL; }
#endif

#define MY_AES256_DEBUGINFO __FUNCTION__, __FILE__, __LINE__
#define MY_AES256_SDEBUGINFO __FILE__, __LINE__

#ifdef MY_AES256_DEBUG
    #define DEBUG_FUNCTION_IN \
	            fprintf (stderr, "** --> call %s (%s:%d)\n", __FUNCTION__, __FILE__, __LINE__)
    #define DEBUG_FUNCTION_OUT \
	            fprintf (stderr, "** <-- exit %s (%s:%d)\n", __FUNCTION__, __FILE__, __LINE__)
#else
    #define DEBUG_FUNCTION_IN
    #define DEBUG_FUNCTION_OUT
#endif

#ifdef MY_AES256_DEBUG
    #define DEBUG_SUB_FUNCTION_IN \
	            fprintf (stderr, " * --> call %s (%s:%d)\n", __FUNCTION__, __FILE__, __LINE__)
    #define DEBUG_SUB_FUNCTION_OUT \
	            fprintf (stderr, " * <-- exit %s (%s:%d)\n", __FUNCTION__, __FILE__, __LINE__)
#else
    #define DEBUG_SUB_FUNCTION_IN
    #define DEBUG_SUB_FUNCTION_OUT
#endif


#ifndef AES256_API
EXPORT_API my_bool lib_mysqludf_aes256_info_init (UDF_INIT * initid, UDF_ARGS * args, char * message);
EXPORT_API void lib_mysqludf_aes256_info_deinit (UDF_INIT * initid);
EXPORT_API char * lib_mysqludf_aes256_info (
	UDF_INIT * initid, UDF_ARGS * args, char * result,
	unsigned long * length, char * null_value, char * error
);

EXPORT_API my_bool aes256_encrypt_init (UDF_INIT * initid, UDF_ARGS * args, char * message);
EXPORT_API void aes256_encrypt_deinit (UDF_INIT * initid);
EXPORT_API char * aes256_encrypt (
	UDF_INIT * initid, UDF_ARGS * args, char * result,
	unsigned long * length, char * null_value, char * error
);

EXPORT_API my_bool aes256_decrypt_init (UDF_INIT * initid, UDF_ARGS * args, char * message);
EXPORT_API void aes256_decrypt_deinit (UDF_INIT * initid);
EXPORT_API char * aes256_decrypt (
	UDF_INIT * initid, UDF_ARGS * args, char * result,
	unsigned long * length, char * null_value, char * error
);
#endif

#endif
