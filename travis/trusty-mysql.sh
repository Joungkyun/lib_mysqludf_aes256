#!/bin/bash

VER=$1

MIRROR="sfo1.mirrors.digitalocean.com"
#MIRROR="ftp.kaist.ac.kr"

case "$VER" in
	'5.5' )
		INSTPKG="mysql-server mysql-client libmysqlclient-dev"
		;;
	'5.6' | '5.7')
		apt-get -y install software-properties-common
		add-apt-repository -y ppa:ondrej/mysql-${VER}

		INSTPKG="mysql-server mysql-client libmysqlclient-dev"
		;;
	*)
		echo "Unsupport version \"$VER\"" > /dev/stdout
		exit 1
esac

if [ -n "${INSTPKG}" ]; then
	apt-get update
	apt-get install -y ${INSTPKG}
fi

exit 0
