CHANGELOG
=========

1.0.0
-----

Breaking changes :

 * `Havelock` and `Sodium` are now `final`
 * `read()` returns false when the session file can not be decrypted (data was left to null and true returned)
 * Registry keys (cookies or `keys()`) must be valid tokens (sha512 hexadecimal), otherwise they are ignored
 * `keys()` replaces the current keys instead of merging them
 * `randomLength()` and `DEFAULT_SSL_RANDOM_LENGTH` removed : they had no effect (the sha512 hash always limited the token to 512 bits)

Other changes :

 * Compatible PHP 7.4 → 8.5 (requires PHP >= 7.4, coercive/cookie ^2, defuse/php-encryption ^2.4)
 * Typed properties, `strict_types`
 * Tokens are `bin2hex(random_bytes(64))` instead of a sha512 hash of `openssl_random_pseudo_bytes()` : same format (128 hexadecimal characters, 512 bits), existing files and cookies stay valid (ext-openssl no longer required directly)
 * Fix : `keys(array $keys = null)` implicit nullable deprecated in PHP 8.4
 * Fix : `destroy()` without previous `read()` did not delete the session file (registry decrypted with the wrong key pair)
 * Fix : `exist()` threw a TypeError when no data was loaded
 * Fix : `kill()` returned false on first run (directory not existing yet)
 * Fix : `kill()` followed symbolic links and deleted their target content
 * Fix : `offload()` deleted nothing when the directory path contained a dot, and failed on systems without `GLOB_BRACE` (Alpine / musl)
 * Fix : path traversal with forged registry keys in `destroy()`
 * Fix : atomic write now uses a temporary file in the target directory (rename across partitions)
 * Fix : `Sodium::seal()` / `unseal()` refused the message "0"
 * Fix : `Sodium::setKeyPair()` left a partial state on invalid key pair
 * PHPUnit tests

0.0.0
-----

 * Born of Coercive Security Havelock
