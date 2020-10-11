lib_mysqludf_aes256
===
[![Build Status](https://travis-ci.org/Joungkyun/lib_mysqludf_aes256.svg?branch=master)](https://travis-ci.org/Joungkyun/lib_mysqludf_aes256) [![GitHub license](https://img.shields.io/badge/license-GPLv2-blue.svg)](https://raw.githubusercontent.com/Joungkyun/lib_mysqludf_aes256/master/COPYING)

Support AES 128/192/256 encrypt and decrypt on MySQL and Maraidb with User Defined Function.

## License

Copyright (c) 2016 JoungKyun.Kim &lt;http://oops.org&gt; All rights reserved.
This program is under [GPL v2](License)

## Requirements

MySQL &lt;= 5.7  
Mariadb &lt;= 10.2

From the version MySQL 5.6.17 and later, you can encode to AES-256 with AES_ENCRYPT function using the ***block_encryption_mode*** global variable. see also http://mysqlblog.fivefarmers.com/2014/03/27/mysql-5-6-17-now-with-better-encryption/. And from version 5.7.4 and later, you can encode to AES-256 with AES_ENCRYPT using 32byte key lentgh. MariaDB does not yet support thie features.

## Usage

 * AES 128 encrypt and decrypt
   * key length : 16byte
   * If the length of the key is 16byte, AES256_ENCRYPT will operate in the same way as AES_ENCRYPT.
```mysql
mysql> select HEX(AES256_ENCRYPT('strings', '0123456789abcdef'));
mysql> select AES256_DECRYPT(UNHEX('encrypted_hash_string'), '0123456789abcdef');
```

 * AES 192 encrypt and decrypt
   * key length : 24byte
```mysql
mysql> select HEX(AES256_ENCRYPT('strings', '0123456789abcdef01234567'));
mysql> select AES256_DECRYPT(UNHEX('encrypted_hash_string'), '0123456789abcdef01234567');
```

 * AES 256 encrypt and decrypt
   * key length : 32byte
```mysql
mysql> select HEX(AES256_ENCRYPT('strings', '0123456789abcdef0123456789abcdef'));
mysql> select AES256_DECRYPT(UNHEX('encrypted_hash_string'), '0123456789abcdef0123456789abcdef');
```

## Installation

* Build and installation
```bash
[root@host lib_mysqludf_aes256]$ ./configure \
        --with-mysql=@MYSQL_PREFIX@ \
        --with-mysql-config=/usr/bin/mysql_config
[root@host lib_mysqludf_aes256]$ make
[root@host lib_mysqludf_aes256]$ make install
```

Before 1.0.4, you must use --with-mysql-plugins-dir instead of --with-mysql-config options.

```bash
[root@host lib_mysqludf_aes256]$ ./configure \
        --with-mysql=@MYSQL_PREFIX@ \
        --with-mysql-plugins-dir="$(mysql_config --plugindir)"
```

If you want to check installed files, you can test install as follow.

```bash
[root@host lib_mysqludf_aes256]$ make test-install
[root@host lib_mysqludf_aes256]$ # OR
[root@host lib_mysqludf_aes256]$ make install DESTDIR=$(pwd)/z
[root@host lib_mysqludf_aes256]$ # chcek test-install files
[root@host lib_mysqludf_aes256]$ tree z # or find ./z
```

* Regist AES256_ENCRYPT/AES256_DECRYPT UDF

```bash
[root@host lib_mysqludf_aes256]$ mysql < docs/aes256_install.sql
```

* Unregist AES256_ENCRYPT/AES256_DECRYPT UDF

```bash
[root@host lib_mysqludf_aes256]$ mysql < docs/aes256_uninstall.sql
```

After installation, aes256_install.sql and aes256_uninstall.sql are located
in PREFIX/share/doc/lib_mysqludf_aes256-@VERSION@/.

## Language API

This UDF function will operate in the same way with follow apis:

  * [javascript mysqlAES package](http://mirror.oops.org/pub/oops/javascript/mysqlAES/)
  * [PHP mysqlAES class](https://github.com/OOPS-ORG-PHP/mysqlAES)

## Credits

JoungKyun.Kim
