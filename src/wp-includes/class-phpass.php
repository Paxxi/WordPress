<?php
/**
 * Portable PHP password hashing framework.
 * @package phpass
 * @since 2.5.0
 * @version 0.3 / WordPress
 * @link http://www.openwall.com/phpass/
 */

#
# Written by Solar Designer <solar at openwall.com> in 2004-2006 and placed in
# the public domain.  Revised in subsequent years, still public domain.
#
# There's absolutely no warranty.
#
# Please be sure to update the Version line if you edit this file in any way.
# It is suggested that you leave the main version number intact, but indicate
# your project name (after the slash) and add your own revision information.
#
# Please do not change the "private" password hashing method implemented in
# here, thereby making your hashes incompatible.  However, if you must, please
# change the hash type identifier (the "$P$") to something different.
#
# Obviously, since this code is in the public domain, the above are not
# requirements (there can be none), but merely suggestions.
#

/**
 * Portable PHP password hashing framework.
 *
 * @package phpass
 * @version 0.3 / WordPress
 * @link http://www.openwall.com/phpass/
 * @since 2.5.0
 */
class PasswordHash {
	var $iteration_count_log2;

	/**
	 * PHP5 constructor.
	 *
	 * @param $iteration_count_log2
	 * @param $portable_hashes
	 */
	function __construct( $iteration_count_log2, $portable_hashes )
	{
		if ($iteration_count_log2 < 4 || $iteration_count_log2 > 31)
			$iteration_count_log2 = 8;
		$this->iteration_count_log2 = $iteration_count_log2;
	}

	function HashPassword($password)
	{
		if ( strlen( $password ) > 4096 ) {
			return '*';
		}

		return password_hash($password, PASSWORD_DEFAULT);
	}

	function CheckPassword($password, $stored_hash)
	{
		if ( empty( $password ) ) {
			return false;
		}

		if ( strlen( $password ) > 4096 ) {
			return false;
		}

		return password_verify($password, $stored_hash);
	}
}
