#!/bin/bash

res=0
echo

# add udf

if [ -f "../docs/aes256_install.sql" ]; then
	mysql -u root < ../docs/aes256_install.sql
else
	mysql -u root < ./docs/aes256_install.sql
fi

[ $? -ne 0 ] && echo "Failed registration UDF" > /dev/stdout && exit 1


# AES-128 test

KEY="0123456789abcdef"

enc=$(mysql -u root -e "select HEX(AES256_ENCRYPT(\"asdf\", \"${KEY}\"))" | tail -n 1)
enc1=$(mysql -u root -e "select HEX(AES_ENCRYPT(\"asdf\", \"${KEY}\"))" | tail -n 1)

if [ "${enc}" = "${enc1}" ]; then
	dec=$(mysql -u root -e "select AES256_DECRYPT(UNHEX(\"${enc}\"), \"${KEY}\")" | tail -n 1)

	if [ "${dec}" = "asdf" ]; then
		echo "Pass: aes192 encrypt and decrypt"
	else
		echo "Failed: aes192 encrypt and decrypt"
		res=1
	fi
else
	echo "Failed: aes128 encrypt"
	res=1
fi


# AES-192 test

KEY="0123456789abcdef01234567"

enc=$(mysql -u root -e "select HEX(AES256_ENCRYPT(\"asdf\", \"${KEY}\"))" | tail -n 1)
dec=$(mysql -u root -e "select AES256_DECRYPT(UNHEX(\"${enc}\"), \"${KEY}\")" | tail -n 1)

if [ "${dec}" = "asdf" ]; then
	echo "Pass: aes192 encrypt and decrypt"
else
	echo "Failed: aes192 encrypt and decrypt"
	res=1
fi

# AES-256 test

KEY="0123456789abcdef0123456789abcdef"

enc=$(mysql -u root -e "select HEX(AES256_ENCRYPT(\"asdf\", \"${KEY}\"))" | tail -n 1)
dec=$(mysql -u root -e "select AES256_DECRYPT(UNHEX(\"${enc}\"), \"${KEY}\")" | tail -n 1)

if [ "${dec}" = "asdf" ]; then
	echo "Pass: aes256 encrypt and decrypt"
else
	echo "Failed: aes256 encrypt and decrypt"
	res=1
fi

exit $res
