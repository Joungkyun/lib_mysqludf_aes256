CC = gcc
CFLAGS = -Wall -O0 -g3 -DMY_AES256_DEBUG
LDFLAGS = 
LIBADD =
CPPFLAGS = -I. -I../../src -I/usr/include/mysql

all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) test.c mysql_aes256_mcrypt.c $(LIBADD) -lmcrypt

crypto:
	$(CC) $(CFLAGS) -DFORCE_CRYPTO $(LDFLAGS) $(CPPFLAGS) test.c mysql_aes256_crypto.c $(LIBADD) -lcrypto
