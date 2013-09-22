#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//#define KEY "01234567890123456789012345678901"
#define KEY "0123456789012345"
//#define KEY "asdf"
//#define DATA "김말똥a 그러나 z쿨!"
#define DATA "김말똥 123123"

#define false 1
#define true 0
#define null NULL

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
typedef char my_bool;

#ifndef safe_free
	#define safe_free(x) if ((x) != NULL) { free(x); x=NULL; }
#endif

my_bool aes256_init_api (AES256_DATA * aes, char * msg);
void aes256_close_api (AES256_DATA * aes);
my_bool aes256_encrypt_api (AES256_DATA * aes);
my_bool aes256_decrypt_api (AES256_DATA * aes);

void aes256_data_init (AES256_DATA * aes) {
	aes->data = null;
	aes->datalen = 0;
	aes->key = null;
	aes->keylen = 0;
	aes->iv = null;
	aes->ivlen = 0;
	aes->keysize = 0;
	aes->blocksize = 0;
	aes->ivsize = 0;
	aes->buffer = null;
	aes->handle = null;
}

AES256_DATA * aes256_encrypt (void) {
	AES256_DATA * aes;
	char msg[1024] = { 0, };

	aes = (AES256_DATA *) malloc (sizeof (AES256_DATA));
	aes256_data_init (aes);

	if ( aes256_init_api (aes, msg) == false ) {
		fprintf (stderr, "%s\n", msg);
		safe_free (aes);
		return NULL;
	}

	aes->data    = (unsigned char *) DATA;
	aes->datalen = strlen (DATA);
	aes->key     = (unsigned char *) KEY;
	aes->keylen  = strlen (KEY);

	if ( aes->keylen > aes->keysize ) {
		fprintf (
			stderr,
			"KEY size is too big (udf: aes256_encrypt)"
		);
		aes256_close_api (aes);
		safe_free (aes);
		return NULL;
	}

	aes->iv = null;
	aes->ivlen = 0;

	if ( aes256_encrypt_api (aes) == false ) {
		fprintf (stderr, "encrypt failed\n");
		return null;
	}

	//result = aes->buffer;
	//*length = (uint) strlen (result);
	aes->datalen = strlen ((char *) aes->buffer);

	return aes;
}

AES256_DATA * aes256_decrypt (char * s) {
	AES256_DATA * aes;
	char msg[1024] = { 0, };

	aes = (AES256_DATA *) malloc (sizeof (AES256_DATA));
	aes256_data_init (aes);

	if ( aes256_init_api (aes, msg) == false ) {
		fprintf (stderr, "%s\n", msg);
		safe_free (aes);
		return NULL;
	}

	aes->data    = (unsigned char *) s;
	aes->datalen = strlen (s);
	aes->key     = (unsigned char *) KEY;
	aes->keylen  = strlen (KEY);
	aes->iv = null;
	aes->ivlen = 0;

	if ( aes256_decrypt_api (aes) == false ) {
		fprintf (stderr, "decrypt failed\n");
		return null;
	}

	//result = aes->buffer;
	//*length = (uint) strlen (result);
	aes->datalen = strlen ((char *) aes->buffer);

	return aes;
}

int main (void) {
	AES256_DATA * aes;
	char * p;

	aes = aes256_encrypt ();
	printf ("--------------------------------------------\n");
	printf ("Length: %u\n", aes->datalen);
	printf ("%s\n", aes->buffer);
	printf ("--------------------------------------------\n");

	p = strdup ((char *) aes->buffer);
	safe_free (aes->buffer);
	safe_free (aes);

	aes = aes256_decrypt (p);
	printf ("--------------------------------------------\n");
	printf ("Length: %u\n", aes->datalen);
	printf ("%s\n", aes->buffer);
	printf ("--------------------------------------------\n");

	safe_free (p);
	safe_free (aes->buffer);
	safe_free (aes);

	return 0;
}
