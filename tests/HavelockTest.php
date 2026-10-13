<?php
namespace Coercive\Security\Havelock\Tests;

use Coercive\Security\Havelock\Havelock;
use PHPUnit\Framework\TestCase;

final class HavelockTest extends TestCase
{
	private string $root;

	private string $dir;

	protected function setUp(): void
	{
		# A dot in the path : offload() must still work
		$this->root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'havelock.test.' . bin2hex(random_bytes(6));
		$this->dir = $this->root . DIRECTORY_SEPARATOR . 'site.com';
	}

	protected function tearDown(): void
	{
		if (is_dir($this->root)) {
			$it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->root, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
			foreach ($it as $file) {
				$file->isDir() && !$file->isLink() ? rmdir($file->getPathname()) : unlink($file->getPathname());
			}
			rmdir($this->root);
		}
	}

	private function havelock(string $password = 'password'): Havelock
	{
		return new Havelock($password, $this->dir);
	}

	private function files(string $sub): array
	{
		return array_values(array_diff(scandir($this->dir . DIRECTORY_SEPARATOR . $sub), ['.', '..']));
	}

	public function testKillOnFirstRun(): void
	{
		$this->assertFalse(is_dir($this->dir));
		$this->assertTrue($this->havelock()->kill());
		$this->assertDirectoryExists($this->dir . '/key');
		$this->assertDirectoryExists($this->dir . '/registry');
		$this->assertDirectoryExists($this->dir . '/session');

		# Again, with content
		$havelock = $this->havelock();
		$this->assertTrue($havelock->create());
		$this->assertTrue($havelock->kill());
		$this->assertSame([], $this->files('registry'));
		$this->assertSame([], $this->files('session'));
		$this->assertSame([], $this->files('key'));
	}

	public function testCreateWithoutDirectories(): void
	{
		$this->assertFalse($this->havelock()->create());
	}

	public function testCreateSaveRead(): void
	{
		$this->havelock()->kill();

		$havelock = $this->havelock();
		$this->assertTrue($havelock->create());
		$keys = $havelock->keys();
		$this->assertCount(3, $keys);
		$this->assertSame(['HAVELOCK_KEY_1', 'HAVELOCK_KEY_2', 'HAVELOCK_KEY_3'], array_keys($keys));
		$this->assertCount(3, $this->files('registry'));
		$this->assertCount(1, $this->files('session'));
		$this->assertCount(2, $this->files('key'));

		# Empty session
		$reader = $this->havelock();
		$this->assertSame($keys, $reader->keys($keys));
		$this->assertTrue($reader->read());
		$this->assertSame([], $reader->data());

		$this->assertTrue($havelock->set('user', 123)->set('test', 'hello')->save());

		$reader = $this->havelock();
		$reader->keys($keys);
		$this->assertTrue($reader->read());
		$this->assertSame(['user' => 123, 'test' => 'hello'], $reader->data());
		$this->assertTrue($reader->exist('user'));
		$this->assertFalse($reader->exist('nope'));
		$this->assertSame('hello', $reader->get('test'));
		$this->assertNull($reader->get('nope'));

		# Session content is encrypted
		$raw = file_get_contents($this->dir . '/session/' . $this->files('session')[0]);
		$this->assertStringNotContainsString('hello', $raw);

		# Wrong password
		$reader = $this->havelock('wrong');
		$reader->keys($keys);
		$this->assertFalse($reader->read());
		$this->assertSame([], $reader->data());
	}

	public function testSaveOverwrite(): void
	{
		$this->havelock()->kill();
		$havelock = $this->havelock();
		$havelock->create();
		$this->assertTrue($havelock->save(['a' => 1]));

		$reader = $this->havelock();
		$reader->keys($havelock->keys());
		$reader->read();
		$this->assertSame(['a' => 1], $reader->data());
	}

	public function testExistWithoutData(): void
	{
		$havelock = $this->havelock();
		$this->assertFalse($havelock->exist('foo'));
		$this->assertSame([], $havelock->data());
		$this->assertFalse($havelock->save());
	}

	public function testInvalidKeys(): void
	{
		$this->havelock()->kill();
		$havelock = $this->havelock();
		$havelock->create();
		$keys = $havelock->keys();

		$reader = $this->havelock();
		$this->assertSame([], $reader->keys([]));
		$this->assertSame([], $reader->keys(array_slice($keys, 0, 2)));
		$this->assertFalse($reader->read());

		$traversal = $keys;
		$traversal['HAVELOCK_KEY_1'] = '../session/' . $this->files('session')[0];
		$this->assertSame([], $reader->keys($traversal));

		# Keys in wrong order
		$reader->keys(array_combine(array_keys($keys), array_reverse(array_values($keys))));
		$this->assertFalse($reader->read());
	}

	public function testCustomKeys(): void
	{
		$this->havelock()->kill();
		$havelock = $this->havelock()->nbKeys(5)->prefixKeys('TEST_KEY_')->name('custom');
		$this->assertTrue($havelock->create());
		$this->assertTrue($havelock->save(['a' => 1]));
		$keys = $havelock->keys();
		$this->assertCount(5, $keys);
		$this->assertArrayHasKey('TEST_KEY_5', $keys);

		$reader = $this->havelock()->nbKeys(5)->prefixKeys('TEST_KEY_')->name('custom');
		$reader->keys($keys);
		$this->assertTrue($reader->read());
		$this->assertSame(['a' => 1], $reader->data());

		# Other name = other registry keypair
		$reader = $this->havelock()->nbKeys(5)->prefixKeys('TEST_KEY_');
		$reader->keys($keys);
		$this->assertFalse($reader->read());
	}

	public function testRefresh(): void
	{
		$this->havelock()->kill();
		$havelock = $this->havelock();
		$havelock->create();
		$havelock->save(['a' => 1]);
		$keys = $havelock->keys();
		$session = $this->files('session');

		# Soft : new registry, same session
		$this->assertTrue($havelock->refresh());
		$soft = $havelock->keys();
		$this->assertCount(3, $soft);
		$this->assertSame([], array_intersect($keys, $soft));
		$this->assertCount(3, $this->files('registry'));
		$this->assertSame($session, $this->files('session'));

		$reader = $this->havelock();
		$reader->keys($keys);
		$this->assertFalse($reader->read());
		$reader = $this->havelock();
		$reader->keys($soft);
		$this->assertTrue($reader->read());
		$this->assertSame(['a' => 1], $reader->data());

		# Hard : new registry, new session, data kept
		$this->assertTrue($reader->refresh(true));
		$this->assertCount(3, $this->files('registry'));
		$this->assertCount(1, $this->files('session'));
		$this->assertNotSame($session, $this->files('session'));

		$reader2 = $this->havelock();
		$reader2->keys($reader->keys());
		$this->assertTrue($reader2->read());
		$this->assertSame(['a' => 1], $reader2->data());

		# Soft refresh without session
		$this->assertFalse($this->havelock()->refresh());
	}

	public function testDestroyWithoutRead(): void
	{
		$this->havelock()->kill();
		$havelock = $this->havelock();
		$havelock->create();
		$havelock->save(['a' => 1]);
		$keys = $havelock->keys();

		# Another instance, only knows the keys
		$other = $this->havelock();
		$other->keys($keys);
		$other->destroy();

		$this->assertSame([], $this->files('registry'));
		$this->assertSame([], $this->files('session'));
		$this->assertSame([], $other->keys());
	}

	public function testDestroyAfterRead(): void
	{
		$this->havelock()->kill();
		$havelock = $this->havelock();
		$havelock->create();
		$reader = $this->havelock();
		$reader->keys($havelock->keys());
		$reader->read();
		$reader->destroy();
		$this->assertSame([], $this->files('registry'));
		$this->assertSame([], $this->files('session'));
		$this->assertSame([], $reader->data());
	}

	public function testOffload(): void
	{
		$this->havelock()->kill();
		$havelock = $this->havelock();
		$havelock->create();
		file_put_contents($this->dir . '/session/.keep', '');

		# Not expired
		$havelock->offload();
		$this->assertCount(3, $this->files('registry'));
		$this->assertCount(2, $this->files('session'));

		$old = time() - 3600;
		foreach (['registry', 'session'] as $sub) {
			foreach ($this->files($sub) as $file) {
				touch($this->dir . "/$sub/$file", $old);
			}
		}
		$havelock->offload(0, 60);
		$this->assertSame([], $this->files('registry'));
		$this->assertSame(['.keep'], $this->files('session'));
		$this->assertCount(2, $this->files('key'));
	}

	public function testKillDoesNotFollowSymlinks(): void
	{
		$outside = $this->root . DIRECTORY_SEPARATOR . 'outside';
		mkdir($outside, 0700, true);
		file_put_contents($outside . '/precious', 'data');

		$this->havelock()->kill();
		symlink($outside, $this->dir . '/link');
		$this->assertTrue($this->havelock()->kill());
		$this->assertFileExists($outside . '/precious');
		$this->assertFalse(is_link($this->dir . '/link'));
	}
}
