lib_mysqludf_aes256
===

Support AES 128/192/256 encrypt and decrypt on MySQL and Maraidb with User Defined Function.

## License

Copyright (c) 2016 JoungKyun.Kim &lt;http://oops.org&gt; All rights reserved.
This program is under [GPL v2](License)

## Requirements

MySQL &lt;= 5.7  
Mariadb &lt;= 10.1

## Usage

 * AES 128 encrypt and decrypt
```mysql
mysql> select HEX(AES256_ENCRYPT('strings', '0123456789abcdef'));
mysql> select AES256_DECRYPT(UNHEX('encrypted_hash_string'), '0123456789abcdef');
```

 * AES 192 encrypt and decrypt
```mysql
mysql> select HEX(AES256_ENCRYPT('strings', '0123456789abcdef01234567'));
mysql> select AES256_DECRYPT(UNHEX('encrypted_hash_string'), '0123456789abcdef01234567');
```

 * AES 256 encrypt and decrypt
```mysql
mysql> select HEX(AES256_ENCRYPT('strings', '0123456789abcdef0123456789abcdef'));
mysql> select AES256_DECRYPT(UNHEX('encrypted_hash_string'), '0123456789abcdef0123456789abcdef');
```

## Installation

* Build and installation
```bash
[root@host lib_mysqludf_aes256]$ # Check mysql(mariadb) plugins dir
[root@host lib_mysqludf_aes256]$ mysql_config --plugindir
/usr/lib64/mysql/plugin
[root@host lib_mysqludf_aes256]$ ./configure \
        --with-mysql=@MYSQL_PREFIX@ \
        --with-mysql-plugins-dir=/usr/lib64/mysql/plugin
[root@host lib_mysqludf_aes256]$ make
[root@host lib_mysqludf_aes256]$ make install
```

If you want to check installed files, you can test install as follow.

```bash
[root@host lib_mysqludf_aes256]$ make test-install
[root@host lib_mysqludf_aes256]$ # OR
[root@host lib_mysqludf_aes256]$ make install DESTDIR=$(pwd)/z
[root@host lib_mysqludf_aes256]$ # chcek test-install files
[root@host lib_mysqludf_aes256]$ tree z # or find ./z
```

* Regist aes256 UDF

```bash
[root@host lib_mysqludf_aes256]$ mysql < doc/aes256_install.sql
```

* Unregist aes256 UDF

```bash
[root@host lib_mysqludf_aes256]$ mysql < doc/aes256_uninstall.sql
```

After installation, aes256_install.sql and aes256_uninstall.sql are located
in PREFIX/share/doc/lib_mysqludf_aes256-@VERSION@/.


## Credits

JoungKyun.Kim
