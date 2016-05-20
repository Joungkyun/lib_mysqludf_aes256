#!/bin/bash

VER=$1

MIRROR="sfo1.mirrors.digitalocean.com"
#MIRROR="ftp.kaist.ac.kr"

case "$VER" in
	'5.5' )
		INSTPKG="mariadb-server mariadb-client libmariadbclient-dev"
		;;
	'10.0' | '10.1' | '10.2')
		apt-get -y install software-properties-common
		apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xcbcb082a1bb943db
		add-apt-repository "deb [arch=amd64,i386] http://${MIRROR}/mariadb/repo/${VER}/ubuntu trusty main"

		INSTPKG="mariadb-server mariadb-client libmariadbclient-dev"
		;;
	*)
		echo "Unsupport version \"$VER\"" > /dev/stdout
		exit 1
esac

apt-get update
apt-get install -y ${INSTPKG}

exit 0
