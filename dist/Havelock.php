<?php
declare(strict_types=1);

namespace Coercive\Security\Havelock;

use Exception;
use SodiumException;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\CryptoException;
use Coercive\Security\Cookie\Cookie;

/**
 * Class Havelock
 *
 * “We play and are played and the best we can hope for is to do it with style.”
 *
 * @package Coercive\Security\Havelock
 * @link https://github.com/Coercive/Havelock
 *
 * @author Anthony Moral <contact@coercive.fr>
 * @copyright 2021 Anthony Moral
 * @license MIT
 *
 * For the full copyright and license information,
 * please view the LICENSE file that was distributed
 * with this source code.
 */
final class Havelock
{
	const NAME = 'havelock';
	const TMP_PREFIX = 'tmp_havelock_';
	const DIR_KEY = 'key';
	const DIR_REGISTRY = 'registry';
	const DIR_SESSION = 'session';

	const HASH_ALGO = 'sha512';
	const DEFAULT_KEYS_NB = 3;
	const DEFAULT_PREFIX_KEYS = 'HAVELOCK_KEY_';
	const DEFAULT_EXPIRE = 365 * 24 * 60 * 60;

	/** Random bytes in a token : 512 bits */
	const TOKEN_BYTES = 64;

	/** Registry and session file names : hexadecimal tokens (2 characters per byte) */
	const TOKEN_PATTERN = '`^[0-9a-f]{128}$`D';

	private Sodium $SodiumRegistry;

	private Sodium $SodiumSession;

	private ? Cookie $cookie = null;

	/** Used as key password */
	private string $password;

	/** The current session name, used for main keys */
	private string $name = self::NAME;

	/** Number of keys / cookies required for bind and open session */
	private int $nbKeys = self::DEFAULT_KEYS_NB;

	/** Name (prefix) of keys / cookies required for bind and open session */
	private string $prefixKeys = self::DEFAULT_PREFIX_KEYS;

	/** Set registry keys in cookies */
	private bool $useCookies = false;

	/** Cookie duration (seconds) */
	private int $expire = self::DEFAULT_EXPIRE;

	/** The main directory */
	private string $mainDir;

	/** The registry key pair directory */
	private string $keyDir;

	/** The registry directory */
	private string $registryDir;

	/** The session data directory */
	private string $sessionDir;

	/** @var string[] */
	private array $keys = [];

	private ? string $session = null;

	private ? array $data = null;

	/**
	 * Alias encrypt
	 *
	 * @param string $str
	 * @return string Empty string on failure
	 */
	private function encrypt(string $str): string
	{
		try {
			return Crypto::encryptWithPassword($str, $this->password);
		}
		catch (CryptoException $e) {
			return '';
		}
	}

	/**
	 * Alias decrypt
	 *
	 * @param string $cipher
	 * @return string Empty string on failure (wrong key, modified cipher)
	 */
	private function decrypt(string $cipher): string
	{
		try {
			return Crypto::decryptWithPassword($cipher, $this->password);
		}
		catch (CryptoException $e) {
			return '';
		}
	}

	/**
	 * Registry token or session id
	 *
	 * @param mixed $token
	 * @return bool
	 */
	private function isToken($token): bool
	{
		return is_string($token) && preg_match(self::TOKEN_PATTERN, $token);
	}

	/**
	 * Path of the encrypted registry secret and public keys
	 *
	 * @return string[]
	 */
	private function registryKeyPaths(): array
	{
		$name = hash(self::HASH_ALGO, $this->name);
		return [
			$this->keyDir . DIRECTORY_SEPARATOR . $name . '.private',
			$this->keyDir . DIRECTORY_SEPARATOR . $name . '.public',
		];
	}

	/**
	 * Load the existing registry keypair (no side effect)
	 *
	 * @return bool
	 */
	private function loadRegistryKeyPair(): bool
	{
		if('' !== $this->SodiumRegistry->getKeyPair()) {
			return true;
		}

		[$private, $public] = $this->registryKeyPaths();
		if(!is_file($private) || !is_file($public)) {
			return false;
		}

		$sk = $this->decrypt((string) file_get_contents($private));
		$pk = $this->decrypt((string) file_get_contents($public));
		if('' === $sk || '' === $pk) {
			return false;
		}

		try {
			$this->SodiumRegistry->setKeys($sk, $pk);
		}
		catch (SodiumException $e) {
			$this->SodiumRegistry->resetKeys();
			return false;
		}
		return true;
	}

	/**
	 * Prepare registry encrypted keypair : load it, or create it when not exists
	 *
	 * @return bool
	 * @throws Exception
	 * @throws SodiumException
	 */
	private function initRegistryKeyPair(): bool
	{
		if($this->loadRegistryKeyPair()) {
			return true;
		}

		[$private, $public] = $this->registryKeyPaths();
		if(is_file($private) && is_file($public)) {
			return false;
		}

		$this->SodiumRegistry->generateKeys();
		$skCiphered = $this->encrypt($this->SodiumRegistry->getSecretKey());
		$pkCiphered = $this->encrypt($this->SodiumRegistry->getPublicKey());
		if('' === $skCiphered || '' === $pkCiphered || !$this->write($private, $skCiphered) || !$this->write($public, $pkCiphered)) {
			$this->SodiumRegistry->resetKeys();
			return false;
		}
		return true;
	}

	/**
	 * Random token (128 hexadecimal characters)
	 *
	 * @return string
	 * @throws Exception
	 */
	private function token(): string
	{
		return bin2hex(random_bytes(self::TOKEN_BYTES));
	}

	/**
	 * Load keys from customer cookies
	 *
	 * @return bool
	 */
	private function loadKeys(): bool
	{
		if(!$this->keys && $this->useCookies) {
			$keys = [];
			foreach (range(1, $this->nbKeys) as $k) {
				$key = $this->prefixKeys . $k;
				$registry = $this->cookie->getSafe($key);
				if($this->isToken($registry)) {
					$keys[$key] = $registry;
				}
			}
			$this->keys = $keys;
		}
		if(count($this->keys) !== $this->nbKeys) {
			$this->keys = [];
			return false;
		}
		return true;
	}

	/**
	 * Decode the registry content
	 *
	 * @param string $serialized
	 * @return array|null ['id' => session id, 'kp' => session keypair]
	 */
	private function decodeRegistryData(string $serialized): ? array
	{
		if('' === $serialized) {
			return null;
		}
		$params = unserialize($serialized, ['allowed_classes' => false]);
		$id = $params['id'] ?? null;
		$kp = $params['kp'] ?? null;
		if(!$this->isToken($id) || !is_string($kp)) {
			return null;
		}
		$kp = base64_decode($kp, true);
		if(!is_string($kp) || '' === $kp) {
			return null;
		}
		return ['id' => $id, 'kp' => $kp];
	}

	/**
	 * Create registry content
	 *
	 * @return string[] Chunks indexed from 1 to nbKeys
	 * @throws Exception
	 */
	private function createRegistryData(): array
	{
		if(!$this->initRegistryKeyPair()) {
			return [];
		}

		$encrypted = $this->SodiumRegistry->seal(serialize([
			'kp' => base64_encode($this->SodiumSession->getKeyPair()),
			'id' => $this->session
		]));

		$length = (int) ceil(strlen($encrypted) / $this->nbKeys);
		$chunks = str_split($encrypted, $length);
		return array_combine(range(1, count($chunks)), $chunks);
	}

	/**
	 * Init new session file
	 *
	 * @return bool
	 * @throws Exception
	 */
	private function createSessionFile(): bool
	{
		do {
			$session = $this->token();
			$path = $this->sessionDir . DIRECTORY_SEPARATOR . $session;
		} while(file_exists($path));

		$this->data = [];
		$this->session = $session;
		$this->SodiumSession->generateKeys();
		return $this->write($path, '');
	}

	/**
	 * Init new registry files
	 *
	 * @return bool
	 * @throws Exception
	 */
	private function createRegistryFiles(): bool
	{
		$this->keys = [];
		$datas = $this->createRegistryData();
		if(count($datas) !== $this->nbKeys) {
			return false;
		}

		$status = true;
		foreach ($datas as $k => $data) {
			$key = $this->prefixKeys . $k;
			do {
				$registry = $this->token();
				$path = $this->registryDir . DIRECTORY_SEPARATOR . $registry;
			} while(file_exists($path));

			$this->keys[$key] = $registry;
			$written = $this->write($path, $data);
			$cooked = true;
			if($this->useCookies) {
				$cooked = $this->cookie->setSafe($key, $registry, time() + $this->expire);
			}
			$status = $status && $written && $cooked;
		}
		return $status;
	}

	/**
	 * Delete all registry files and cookies
	 *
	 * @return string The session id contained in registry (only if the current session is not loaded)
	 */
	private function deleteRegistryFiles(): string
	{
		$raw = '';
		$complete = true;
		foreach (range(1, $this->nbKeys) as $k) {
			$key = $this->prefixKeys . $k;
			$registry = $this->keys[$key] ?? '';
			if('' === $registry && $this->useCookies) {
				$registry = $this->cookie->getSafe($key);
			}

			$path = $this->registryDir . DIRECTORY_SEPARATOR . $registry;
			if($this->isToken($registry) && is_file($path)) {
				$chunk = file_get_contents($path);
				if(is_string($chunk) && '' !== $chunk) {
					$raw .= $chunk;
				}
				else {
					$complete = false;
				}
				unlink($path);
			}
			else {
				$complete = false;
			}

			if($this->useCookies) {
				$this->cookie->delete($key);
			}
		}

		if(null === $this->session && $complete && '' !== $raw && $this->loadRegistryKeyPair()) {
			try {
				$params = $this->decodeRegistryData($this->SodiumRegistry->unseal($raw));
			}
			catch (Exception $e) {
				return '';
			}
			return $params['id'] ?? '';
		}
		return '';
	}

	/**
	 * Delete session file
	 *
	 * @param string|null $session [optional]
	 * @return void
     */
	private function deleteSessionFile(? string $session = null): void
    {
		foreach ([$session, $this->session] as $id) {
			if($this->isToken($id)) {
				$path = $this->sessionDir . DIRECTORY_SEPARATOR . $id;
				if(is_file($path)) {
					unlink($path);
				}
			}
		}
    }

	/**
	 * Remove directory recursively (symbolic links are removed, not followed)
	 *
	 * @param string $directory
	 * @return bool
	 */
	private function rmdir(string $directory): bool
	{
		$files = scandir($directory);
		if(false === $files) {
			return false;
		}
		$status = true;
		foreach ($files as $file) {
			if ('.' === $file || '..' === $file) {
				continue;
			}
			$path = $directory . DIRECTORY_SEPARATOR . $file;
			$deleted = is_dir($path) && !is_link($path) ? $this->rmdir($path) : unlink($path);
			$status = $deleted && $status;
		}
		return rmdir($directory) && $status;
	}

	/**
	 * Create all directories
	 *
	 * @return bool
	 */
	private function mkdir(): bool
	{
		$directory = is_dir($this->mainDir) || mkdir($this->mainDir, 0700, true);
		$key = is_dir($this->keyDir) || mkdir($this->keyDir, 0700, true);
		$registry = is_dir($this->registryDir) || mkdir($this->registryDir, 0700, true);
		$session = is_dir($this->sessionDir) || mkdir($this->sessionDir, 0700, true);
		return $directory && $key && $registry && $session;
	}

	/**
	 * Write to temp file first (in the same directory) to ensure atomicity
	 *
	 * @link https://blogs.msdn.microsoft.com/adioltean/2005/12/28/how-to-do-atomic-writes-in-a-file
	 *
	 * @param string $path
	 * @param string $data
	 * @return bool False if the directory does not exist
	 * @throws Exception
	 */
	private function write(string $path, string $data): bool
	{
		$directory = dirname($path);
		if(!is_dir($directory)) {
			return false;
		}
		$tmp = tempnam($directory, self::TMP_PREFIX);
		if (false === $tmp) {
			throw new Exception("Can't create temporary file in : $directory");
		}
		if (false === file_put_contents($tmp, $data, LOCK_EX)) {
			unlink($tmp);
			throw new Exception("Can't write data in file : $tmp");
		}
		if(!chmod($tmp, 0600) || !rename($tmp, $path)) {
			if(is_file($tmp)) {
				unlink($tmp);
			}
			return false;
		}
		return true;
	}

	/**
	 * Havelock constructor.
	 *
	 * @param string $password
	 * @param string $directory
	 * @param Cookie|null $cookie [optional]
	 */
	public function __construct(string $password, string $directory, ? Cookie $cookie = null)
	{
		$this->password = $password;

		$this->mainDir = $directory;
		$this->keyDir = $directory . DIRECTORY_SEPARATOR . self::DIR_KEY;
		$this->registryDir = $directory . DIRECTORY_SEPARATOR . self::DIR_REGISTRY;
		$this->sessionDir = $directory . DIRECTORY_SEPARATOR . self::DIR_SESSION;

		if($cookie) {
			$this->cookie = $cookie;
			$this->useCookies = true;
		}

		$this->SodiumRegistry = new Sodium;
		$this->SodiumSession = new Sodium;
	}

	/**
	 * Session name
	 *
	 * @param string $name
	 * @return Havelock
	 */
	public function name(string $name): self
	{
		$this->name = $name;
		return $this;
	}

	/**
	 * Cookie max lifetime
	 *
	 * @param int $seconds
	 * @return Havelock
	 */
	public function expire(int $seconds): self
	{
		$this->expire = $seconds;
		return $this;
	}

	/**
	 * Set/unset registry keys in cookies
	 *
	 * @param bool $status [optional]
	 * @param Cookie|null $cookie [optional]
	 * @return Havelock
	 */
	public function cookie(bool $status = false, ? Cookie $cookie = null): self
	{
		if($cookie) {
			$this->cookie = $cookie;
		}
		$this->useCookies = $status && $this->cookie;
		return $this;
	}

	/**
	 * Number of keys / cookies required for bind and open session
	 *
	 * @param int $nb [optional]
	 * @return Havelock
	 */
	public function nbKeys(int $nb = self::DEFAULT_KEYS_NB): self
	{
		if($nb >= 1) {
			$this->nbKeys = $nb;
		}
		return $this;
	}

	/**
	 * Name (prefix) of keys / cookies required for bind and open session
	 *
	 * @param string $name [optional]
	 * @return Havelock
	 */
	public function prefixKeys(string $name = self::DEFAULT_PREFIX_KEYS): self
	{
		if('' !== $name) {
			$this->prefixKeys = $name;
		}
		return $this;
	}

	/**
	 * Expose/Inject registry keys
	 *
	 * Injected keys must all be present and valid, otherwise keys are reset.
	 *
	 * @param array|null $keys [optional]
	 * @return string[]
	 */
	public function keys(? array $keys = null): array
	{
		if(null === $keys) {
			return $this->keys;
		}
		if(!$keys) {
			return [];
		}

		$valid = [];
		foreach (range(1, $this->nbKeys) as $k) {
			$key = $this->prefixKeys . $k;
			$registry = $keys[$key] ?? '';
			if($this->isToken($registry)) {
				$valid[$key] = $registry;
			}
		}
		$this->keys = count($valid) === $this->nbKeys ? $valid : [];
		return $this->keys;
	}

	/**
	 * Generate customer session
	 *
	 * @return bool
	 * @throws Exception
	 */
	public function create(): bool
	{
		return $this->createSessionFile() && $this->createRegistryFiles();
	}

	/**
	 * Refresh registry tokens
	 *
	 * @param bool $hard [optional] Also renew the session id and key pair
	 * @return bool
	 * @throws Exception
	 */
	public function refresh(bool $hard = false): bool
	{
		if($hard) {
			$saved = true;
			$data = $this->data;
			$this->destroy();
			$created = $this->create();
			if($data) {
				$saved = $this->save($data);
			}
			return $created && $saved;
		}

		if(null === $this->session || '' === $this->SodiumSession->getKeyPair() || '' === $this->SodiumRegistry->getKeyPair()) {
			return false;
		}
		$this->deleteRegistryFiles();
		return $this->createRegistryFiles();
	}

	/**
	 * Try to load an existing session
	 *
	 * @return bool
	 * @throws SodiumException
	 * @throws Exception
	 */
	public function read(): bool
	{
		$this->data = null;

		if(!$this->loadKeys()) {
			return false;
		}

		if(!$this->loadRegistryKeyPair()) {
			return false;
		}

		if(null === $this->session || '' === $this->SodiumSession->getKeyPair()) {
			$raw = '';
			foreach ($this->keys as $registry) {
				$path = $this->registryDir . DIRECTORY_SEPARATOR . $registry;
				$chunk = is_file($path) ? file_get_contents($path) : false;
				if(!is_string($chunk) || '' === $chunk) {
					return false;
				}
				$raw .= $chunk;
			}

			$params = $this->decodeRegistryData($this->SodiumRegistry->unseal($raw));
			if(null === $params) {
				return false;
			}
			try {
				$this->SodiumSession->setKeyPair($params['kp']);
			}
			catch (SodiumException $e) {
				$this->SodiumSession->resetKeys();
				return false;
			}
			$this->session = $params['id'];
		}

		$path = $this->sessionDir . DIRECTORY_SEPARATOR . $this->session;
		$raw = is_file($path) ? file_get_contents($path) : false;
		if(false === $raw) {
			return false;
		}
		if('' === $raw) {
			$this->data = [];
			return true;
		}

		$serialized = $this->SodiumSession->unseal($raw);
		$data = '' !== $serialized ? unserialize($serialized) : null;
		if(!is_array($data)) {
			return false;
		}
		$this->data = $data;
		return true;
	}

	/**
	 * Save data in current session.
	 *
	 * @param array|null $overwrite [optional]
	 * @return bool
	 * @throws SodiumException
	 * @throws Exception
	 */
	public function save(? array $overwrite = null): bool
	{
		if(null === $this->session || '' === $this->SodiumSession->getKeyPair()) {
			return false;
		}
		$path = $this->sessionDir . DIRECTORY_SEPARATOR . $this->session;
		if(!is_file($path)) {
			return false;
		}
		if(null !== $overwrite) {
			$this->data = $overwrite;
		}
		$encrypted = $this->SodiumSession->seal(serialize($this->data ?? []));
		return $this->write($path, $encrypted);
	}

	/**
	 * Expose current session data.
	 *
	 * @param array|null $overwrite [optional]
	 * @return array
	 */
	public function data(? array $overwrite = null): array
	{
		if(null !== $overwrite) {
			$this->data = $overwrite;
		}
		return $this->data ?? [];
	}

	/**
	 * Entry exist in session data
	 *
	 * @param string $key
	 * @return bool
	 */
	public function exist(string $key): bool
	{
		return array_key_exists($key, $this->data ?? []);
	}

	/**
	 * Return the targeted entry
	 *
	 * @param string $key
	 * @return mixed|null
	 */
	public function get(string $key)
	{
		return $this->data[$key] ?? null;
	}

	/**
	 * Set the targeted entry
	 *
	 * @param string $key
	 * @param mixed|null $value [optional]
	 * @return Havelock
	 */
	public function set(string $key, $value = null): self
	{
		$this->data[$key] = $value;
		return $this;
	}

	/**
	 * Offload expired sessions.
	 *
	 * @param int $rand [optional] Probability 1/($rand + 1) to run, 0 = always
	 * @param int|null $expire [optional] Seconds, default : cookie lifetime
	 * @return Havelock
	 */
	public function offload(int $rand = 0, ? int $expire = null): self
	{
		$max = PHP_INT_MIN === $rand ? PHP_INT_MAX : abs($rand);
		if(0 !== mt_rand(0, $max)) {
			return $this;
		}

		$now = time();
		if(null === $expire) {
			$expire = $this->expire;
		}

		foreach ([$this->registryDir, $this->sessionDir] as $directory) {
			$files = is_dir($directory) ? scandir($directory) : false;
			foreach ($files ?: [] as $file) {
				if(!$this->isToken($file)) {
					continue;
				}
				$path = $directory . DIRECTORY_SEPARATOR . $file;
				$time = is_file($path) ? filemtime($path) : false;
				if(false !== $time && $now - $time >= $expire) {
					unlink($path);
				}
			}
		}
		return $this;
	}

	/**
	 * Destroy an existing customer session
	 *
	 * @return Havelock
	 */
	public function destroy(): self
	{
		$session = $this->deleteRegistryFiles();
		$this->deleteSessionFile($session);

		$this->keys = [];
		$this->session = null;
		$this->SodiumSession->resetKeys();
		$this->data = null;
		return $this;
	}

	/**
	 * Init new empty registry and sessions (remove all and create directories).
	 *
	 * @return bool
	 */
	public function kill(): bool
	{
		$this->destroy();
		$this->SodiumRegistry->resetKeys();
		$rmdir = !is_dir($this->mainDir) || $this->rmdir($this->mainDir);
		$mkdir = $this->mkdir();
		return $rmdir && $mkdir;
	}
}