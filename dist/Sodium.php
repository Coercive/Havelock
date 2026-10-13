<?php
declare(strict_types=1);

namespace Coercive\Security\Havelock;

use Exception;
use SodiumException;

/**
 * Sodium Handler
 *
 * Anonymous public key encryption (sealed box) : seal with the public key, unseal with the key pair.
 *
 * @package Coercive\Security\Havelock
 *
 * @author Anthony Moral <contact@coercive.fr>
 * @copyright 2021 Anthony Moral
 * @license MIT
 */
final class Sodium
{
	private string $keyPair = '';

	private string $publicKey = '';

	private string $secretKey = '';

	/**
	 * @return string
	 */
	public function getKeyPair(): string
	{
		return $this->keyPair;
	}

	/**
	 * @return string
	 */
	public function getPublicKey(): string
	{
		return $this->publicKey;
	}

	/**
	 * @return string
	 */
	public function getSecretKey(): string
	{
		return $this->secretKey;
	}

	/**
	 * @return Sodium
	 */
	public function resetKeys(): self
	{
		$this->keyPair = '';
		$this->publicKey = '';
		$this->secretKey = '';
		return $this;
	}

	/**
	 * Generate Sodium key pair
	 *
	 * @return Sodium
	 * @throws SodiumException
	 */
	public function generateKeys(): self
	{
		return $this->setKeyPair(sodium_crypto_box_keypair());
	}

	/**
	 * Set key pair / and build alias public and secret key
	 *
	 * @param string $keyPair
	 * @return Sodium
	 * @throws SodiumException Invalid key pair
	 */
	public function setKeyPair(string $keyPair): self
	{
		$secretKey = sodium_crypto_box_secretkey($keyPair);
		$publicKey = sodium_crypto_box_publickey($keyPair);
		$this->keyPair = $keyPair;
		$this->secretKey = $secretKey;
		$this->publicKey = $publicKey;
		return $this;
	}

	/**
	 * Set public and secret key and build full key pair
	 *
	 * @param string $secretKey
	 * @param string $publicKey
	 * @return Sodium
	 * @throws SodiumException Invalid keys
	 */
	public function setKeys(string $secretKey, string $publicKey): self
	{
		$this->keyPair = sodium_crypto_box_keypair_from_secretkey_and_publickey($secretKey, $publicKey);
		$this->secretKey = $secretKey;
		$this->publicKey = $publicKey;
		return $this;
	}

	/**
	 * Seal the message
	 *
	 * @param string $message
	 * @return string
	 * @throws Exception Public key not initialized or empty message
	 * @throws SodiumException
	 */
	public function seal(string $message): string
	{
		if('' === $this->publicKey) {
			throw new Exception('Sodium: public key is not initialized.');
		}
		if('' === $message) {
			throw new Exception('Sodium: no message to seal.');
		}
		return sodium_crypto_box_seal($message, $this->publicKey);
	}

	/**
	 * Unseal the cipher text
	 *
	 * @param string $cipherText
	 * @return string Empty string on failure (wrong key, modified cipher)
	 * @throws Exception Key pair not initialized or empty cipher text
	 * @throws SodiumException
	 */
	public function unseal(string $cipherText): string
	{
		if('' === $this->keyPair) {
			throw new Exception('Sodium: key pair is not initialized.');
		}
		if('' === $cipherText) {
			throw new Exception('Sodium: no cipher text to unseal.');
		}
		return (string) sodium_crypto_box_seal_open($cipherText, $this->keyPair);
	}
}
