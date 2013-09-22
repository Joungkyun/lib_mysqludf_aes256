#
#                       Written by JoungKyun.Kim
#            Copyright (c) 2013 JoungKyun.Kim <http://oops.org>
#
# -----------------------------------------------------------------------------
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------------
# This file is part of lib_mysqludf_aes256.
#
# $Id$

lib_LTLIBRARIES =

AM_CFLAGS = -Wall
AM_LDFLAGS = -module -avoid-version
AM_CPPFLAGS = -I$(top_srcdir)

BUILT_SOURCES = mysql_aes256_config.h
noinst_HEADERS = mysql_aes256.h

lib_LTLIBRARIES += lib_mysqludf_aes256.la
lib_mysqludf_aes256_la_SOURCES  = mysql_aes256.c my_aes.c
lib_mysqludf_aes256_la_LIBADD   = -lpthread
lib_mysqludf_aes256_la_CFLAGS   = -DMYSQL_SERVER
#lib_mysqludf_aes256_la_CFLAGS   = -DSTANDARD -DMYSQL_SERVER
lib_mysqludf_aes256_la_CPPFLAGS = @MYSQL_HEADER@

DISTCLEANFILES = *~
