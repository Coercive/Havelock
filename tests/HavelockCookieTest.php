<?php
namespace Coercive\Security\Havelock\Tests;

use Coercive\Security\Cookie\Cookie;
use Coercive\Security\Havelock\Havelock;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;

/**
 * setcookie() needs headers not sent yet : each test runs in its own process.
 */
#[RunTestsInSeparateProcesses]
final class HavelockCookieTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$_COOKIE = [];
		$this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'havelock_cookie_' . bin2hex(random_bytes(6));
	}

	protected function tearDown(): void
	{
		(new Havelock('password', $this->dir))->kill();
		rmdir($this->dir . '/key');
		rmdir($this->dir . '/registry');
		rmdir($this->dir . '/session');
		rmdir($this->dir);
	}

	public function testCookieRoundTrip(): void
	{
		$cookie = (new Cookie('cookie password'))->anonymize(true, 'salt', 'pre_');

		$havelock = new Havelock('password', $this->dir, $cookie);
		$this->assertTrue($havelock->kill());
		$this->assertTrue($havelock->create());
		$this->assertTrue($havelock->save(['user' => 42]));
		$this->assertCount(3, $_COOKIE);

		# Next request : keys come from cookies
		$reader = new Havelock('password', $this->dir, $cookie);
		$this->assertTrue($reader->read());
		$this->assertSame(42, $reader->get('user'));

		# Disabled cookies : no keys
		$reader = (new Havelock('password', $this->dir, $cookie))->cookie(false);
		$this->assertFalse($reader->read());

		# Destroy removes cookies, registry and session
		(new Havelock('password', $this->dir, $cookie))->destroy();
		$this->assertSame([], $_COOKIE);
		$this->assertSame(['.', '..'], scandir($this->dir . '/registry'));
		$this->assertSame(['.', '..'], scandir($this->dir . '/session'));
	}
}
