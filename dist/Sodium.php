<?php
namespace Coercive\Security\Havelock;

use Exception;
use SodiumException;

/**
 * Sodium Handler
 */
class Sodium
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
	public function resetKeys(): Sodium
	{
		$this->keyPair = '';
		$this->publicKey = '';
		$this->secretKey = '';
		return $this;
	}

	/**
	 * Generate Sodium key pair
	 *
	 * @return $this
	 * @throws SodiumException
	 */
	public function generateKeys(): Sodium
	{
		return $this->setKeyPair(sodium_crypto_box_keypair());
	}

	/**
	 * Set key pair / and build alias public and secret key
	 *
	 * @param string $keyPair
	 * @return $this
	 * @throws SodiumException
	 */
	public function setKeyPair(string $keyPair): Sodium
	{
		$this->keyPair = $keyPair;
		$this->secretKey = sodium_crypto_box_secretkey($this->keyPair);
		$this->publicKey = sodium_crypto_box_publickey($this->keyPair);
		return $this;
	}

	/**
	 * Set public and secret key and build full key pair
	 *
	 * @param string $secretKey
	 * @param string $publicKey
	 * @return $this
	 * @throws SodiumException
	 */
	public function setKeys(string $secretKey, string $publicKey): Sodium
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
	 * @throws SodiumException
	 */
	public function seal(string $message): string
	{
		if(!$this->publicKey) {
			throw new Exception('Sodium: public key is not initialized.');
		}
		if(!$message) {
			throw new Exception('Sodium: no message to seal.');
		}
		return sodium_crypto_box_seal($message, $this->publicKey);
	}

	/**
	 * Unseal the cipher text
	 *
	 * @param string $cipherText
	 * @return string
	 * @throws SodiumException
	 */
	public function unseal(string $cipherText): string
	{
		if(!$this->keyPair) {
			throw new Exception('Sodium: key pair is not initialized.');
		}
		if(!$cipherText) {
			throw new Exception('Sodium: no cipher text to unseal.');
		}
		return (string) sodium_crypto_box_seal_open($cipherText, $this->keyPair);
	}
}