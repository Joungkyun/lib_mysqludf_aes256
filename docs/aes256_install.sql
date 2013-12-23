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

use mysql;

DROP FUNCTION IF EXISTS lib_mysqludf_aes256_info;
DROP FUNCTION IF EXISTS aes256_encrypt;
DROP FUNCTION IF EXISTS aes256_decrypt;

CREATE FUNCTION lib_mysqludf_aes256_info RETURNS string SONAME 'lib_mysqludf_aes256.so';
CREATE FUNCTION aes256_encrypt RETURNS string SONAME 'lib_mysqludf_aes256.so';
CREATE FUNCTION aes256_decrypt RETURNS string SONAME 'lib_mysqludf_aes256.so';
