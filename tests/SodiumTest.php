<?php
namespace Coercive\Security\Havelock\Tests;

use Coercive\Security\Havelock\Sodium;
use Exception;
use PHPUnit\Framework\TestCase;
use SodiumException;

final class SodiumTest extends TestCase
{
	public function testSealUnseal(): void
	{
		$sodium = (new Sodium)->generateKeys();
		$this->assertSame(SODIUM_CRYPTO_BOX_KEYPAIRBYTES, strlen($sodium->getKeyPair()));
		$this->assertSame(SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, strlen($sodium->getPublicKey()));
		$this->assertSame(SODIUM_CRYPTO_BOX_SECRETKEYBYTES, strlen($sodium->getSecretKey()));

		$cipher = $sodium->seal('hello');
		$this->assertNotSame('hello', $cipher);
		$this->assertSame('hello', $sodium->unseal($cipher));

		# "0" is a valid message
		$this->assertSame('0', $sodium->unseal($sodium->seal('0')));
	}

	public function testSetKeysAndKeyPair(): void
	{
		$sodium = (new Sodium)->generateKeys();
		$cipher = $sodium->seal('hello');

		$fromKeys = (new Sodium)->setKeys($sodium->getSecretKey(), $sodium->getPublicKey());
		$this->assertSame($sodium->getKeyPair(), $fromKeys->getKeyPair());
		$this->assertSame('hello', $fromKeys->unseal($cipher));

		$fromKeyPair = (new Sodium)->setKeyPair($sodium->getKeyPair());
		$this->assertSame($sodium->getPublicKey(), $fromKeyPair->getPublicKey());
		$this->assertSame('hello', $fromKeyPair->unseal($cipher));

		# Seal with public key only
		$public = new Sodium;
		$this->assertSame('hello', $sodium->unseal($fromKeys->seal('hello')));
		$this->assertSame('', $public->getKeyPair());
	}

	public function testUnsealWrongKey(): void
	{
		$cipher = (new Sodium)->generateKeys()->seal('hello');
		$this->assertSame('', (new Sodium)->generateKeys()->unseal($cipher));
		$this->assertSame('', (new Sodium)->generateKeys()->unseal('short'));
	}

	public function testInvalidKeyPair(): void
	{
		$sodium = new Sodium;
		try {
			$sodium->setKeyPair('invalid');
			$this->fail('SodiumException expected');
		}
		catch (SodiumException $e) {
			$this->assertSame('', $sodium->getKeyPair());
			$this->assertSame('', $sodium->getPublicKey());
		}
	}

	public function testReset(): void
	{
		$sodium = (new Sodium)->generateKeys()->resetKeys();
		$this->assertSame('', $sodium->getKeyPair());
		$this->assertSame('', $sodium->getPublicKey());
		$this->assertSame('', $sodium->getSecretKey());
	}

	public function testSealWithoutKey(): void
	{
		$this->expectException(Exception::class);
		(new Sodium)->seal('hello');
	}

	public function testSealEmptyMessage(): void
	{
		$this->expectException(Exception::class);
		(new Sodium)->generateKeys()->seal('');
	}

	public function testUnsealWithoutKey(): void
	{
		$this->expectException(Exception::class);
		(new Sodium)->unseal('cipher');
	}
}
