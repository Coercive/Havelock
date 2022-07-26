<?php
namespace Coercive\Security\Havelock;

use Exception;
use TypeError;
use SodiumException;
use Defuse\Crypto\Crypto;
use Coercive\Security\Cookie\Cookie;

/**
 * Class Havelock
 *
 * “We play and are played and the best we can hope for is to do it with style.”
 *
 * @package 	Coercive\Security\Havelock
 * @link		https://github.com/Coercive/Havelock
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2021 Anthony Moral
 * @license 	MIT
 *
 * For the full copyright and license information,
 * please view the LICENSE file that was distributed
 * with this source code.
 */
class Havelock
{
	const NAME = 'havelock';
	const TMP_PREFIX = 'tmp_havelock_';
	const DIR_KEY = 'key';
	const DIR_REGISTRY = 'registry';
	const DIR_SESSION = 'session';

	const HASH_ALGO = 'sha512';
	const DEFAULT_SSL_RANDOM_LENGTH = 128;
	const DEFAULT_KEYS_NB = 3;
	const DEFAULT_PREFIX_KEYS = 'HAVELOCK_KEY_';
	const DEFAULT_EXPIRE = 365 * 24 * 60 * 60;

	/** @var Sodium */
	private Sodium $SodiumRegistry;

	/** @var Sodium */
	private Sodium $SodiumSession;

	/** @var Cookie|null */
	private ? Cookie $cookie = null;

	/** @var string Used as key password */
	private string $password;

	/** @var string The current session name, used for main keys */
	private string $name = self::NAME;

	/** @var int Number of keys / cookies required for bind and open session */
	private int $nbKeys = self::DEFAULT_KEYS_NB;

	/** @var string Name (prefix) of keys / cookies required for bind and open session */
	private string $prefixKeys = self::DEFAULT_PREFIX_KEYS;

	/** @var int Openssl random pseudo bytes length */
	private int $randomLength = self::DEFAULT_SSL_RANDOM_LENGTH;

	/** @var bool Set registry keys in cookies */
	private bool $useCookies = false;

	/** @var int Cookie duration */
	private int $expire;

	/** @var string The main directory */
	private string $mainDir;

	/** @var string The registry directory */
	private string $keyDir;

	/** @var string The registry directory */
	private string $registryDir;

	/** @var string The session data directory */
	private string $sessionDir;

	/** @var string[] */
	private array $keys = [];

	/** @var string|null */
	private ? string $session = null;

	/** @var array|null */
	private ? array $data = null;

	/**
	 * Alias encrypt
	 *
	 * @param string $str
	 * @return string
	 */
	private function encrypt(string $str): string
	{
		try {
			return Crypto::encryptWithPassword($str, $this->password);
		}
		catch (Exception $e) {
			return '';
		}
	}

	/**
	 * Alias decrypt
	 *
	 * @param string $cipher
	 * @return string
	 */
	private function decrypt(string $cipher): string
	{
		try {
			return Crypto::decryptWithPassword($cipher, $this->password);
		}
		catch (Exception $e) {
			return '';
		}
	}

	/**
	 * Prepare registry encrypted keypair
	 *
	 * @return bool
	 * @throws Exception
	 * @throws SodiumException
	 */
	private function initRegistryKeyPair(): bool
	{
		if($this->SodiumRegistry->getKeyPair()) {
			return true;
		}

		$name = hash(self::HASH_ALGO, $this->name);
		$private = $this->keyDir . DIRECTORY_SEPARATOR . $name . '.private';
		$public = $this->keyDir . DIRECTORY_SEPARATOR . $name . '.public';
		if(is_file($private) && is_file($public)) {
			$skCiphered = file_get_contents($private);
			$pkCiphered = file_get_contents($public);
			if($skCiphered && $pkCiphered) {
				$sk = $this->decrypt($skCiphered);
				$pk = $this->decrypt($pkCiphered);
				if($sk && $pk) {
					$this->SodiumRegistry->setKeys($sk, $pk);
				}
			}
		}

		else {
			$this->SodiumRegistry->generateKey();
			$skCiphered = $this->encrypt($this->SodiumRegistry->getSecretKey());
			$pkCiphered = $this->encrypt($this->SodiumRegistry->getPublicKey());
			if($skCiphered && $pkCiphered) {
				$skSaved = $this->write($private, $skCiphered);
				$pkSaved = $this->write($public, $pkCiphered);
				if(!$skSaved || !$pkSaved) {
					$this->SodiumRegistry->resetKeys();
				}
			}
		}

		return (bool) $this->SodiumRegistry->getKeyPair();
	}

	/**
	 * OpenSSL random pseudo bytes
	 *
	 * @return string
	 */
	private function token(): string
	{
		return hash(self::HASH_ALGO, openssl_random_pseudo_bytes($this->randomLength), false);
	}

	/**
	 * Load keys from customer cookies
	 *
	 * @return bool
	 */
	private function loadKeys(): bool
	{
		if(!$this->keys && $this->useCookies) {
			foreach (range(1, $this->nbKeys) as $k) {
				$key = $this->prefixKeys . $k;
				$registry = $this->cookie->getSafe($key);
				if($registry) {
					$this->keys[$key] = $registry;
				}
			}
		}
		if(count($this->keys) !== $this->nbKeys) {
			$this->keys = [];
			return false;
		}
		return true;
	}

	/**
	 * Create registry content
	 *
	 * @return array
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

		$length = ceil(strlen($encrypted) / $this->nbKeys);
		$chunks = str_split($encrypted, $length);

		array_unshift($chunks,'');
		unset($chunks[0]);
		return $chunks;
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
			if(!file_exists($path)) {
				break;
			}
		} while(true);
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
	private function createRegistyFiles(): bool
	{
		$this->keys = [];
		$datas = $this->createRegistryData();
		$range = range(1, $this->nbKeys);
		$keys = array_keys($datas);
		if(!$datas || count($range) !== count($keys) || array_diff($range, $keys)) {
			return false;
		}

		$status = true;
		foreach ($range as $k) {
			$key = $this->prefixKeys . $k;
			do {
				$registry = $this->token();
				$path = $this->registryDir . DIRECTORY_SEPARATOR . $registry;
				if(!file_exists($path)) {
					break;
				}
			} while(true);
			$this->keys[$key] = $registry;
			$written = $this->write($path, $datas[$k]);
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
	 * @return string List of sessions token contains in registry keys
	 * @throws SodiumException
	 */
	private function deleteRegistryFiles(): string
	{
		$session = '';
		foreach (range(1, $this->nbKeys) as $k) {
			$key = $this->prefixKeys . $k;
			$registry = $this->keys[$key] ?? '';
			if(!$registry && $this->useCookies) {
				$registry = $this->cookie->getSafe($key);
			}
			if($registry) {
				$path = $this->registryDir . DIRECTORY_SEPARATOR . $registry;
				if(!$this->session && is_file($path) && $chunk = file_get_contents($path)) {
					$session .= $chunk;
				}
				if(is_file($path)) {
					unlink($path);
				}
			}
			if($this->useCookies) {
				$this->cookie->delete($this->prefixKeys . $k);
			}
		}
		if($session && $this->SodiumSession->getKeyPair()) {
			$decrypted = $this->SodiumSession->unseal($session);
			$data = $decrypted ? unserialize($decrypted) : null;
			return strval($data['id'] ?? '');
		}
		return '';
	}

	/**
	 * Delete session file
	 *
	 * @param string|null $session [optional]
	 * @return bool
	 */
	private function deleteSessionFile(? string $session = null): bool
	{
		if($session) {
			$path = $this->sessionDir . DIRECTORY_SEPARATOR . $session;
			if(is_file($path)) {
				unlink($path);
			}
		}
		if($this->session) {
			$path = $this->sessionDir . DIRECTORY_SEPARATOR . $this->session;
			if(is_file($path)) {
				unlink($path);
			}
		}
		return true;
	}

	/**
	 * Remove all
	 *
	 * @param string|null $directory [optional]
	 * @return bool
	 */
	private function rmdir(? string $directory = null): bool
	{
		if(!$directory) {
			$directory = $this->mainDir;
		}
		if (!is_dir($directory)) {
			return false;
		}
		$dir = opendir($directory);
		while (false !== ($file = readdir($dir))) {
			if ($file !== '.' && $file !== '..') {
				$path = $directory . DIRECTORY_SEPARATOR . $file;
				if (is_dir($path)) {
					$this->rmdir($path);
				}
				else {
					unlink($path);
				}
			}
		}
		closedir($dir);
		return rmdir($directory);
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
	 * Write to temp file first to ensure atomicity
	 *
	 * @link https://blogs.msdn.microsoft.com/adioltean/2005/12/28/how-to-do-atomic-writes-in-a-file
	 *
	 * @param string $path
	 * @param string $data
	 * @return bool
	 * @throws Exception
	 */
	private function write(string $path, string $data): bool
	{
		$tmp = tempnam(sys_get_temp_dir(), self::TMP_PREFIX);
		$bytes = file_put_contents($tmp, $data, LOCK_EX);
		if (false === $bytes) {
			throw new Exception("Can't write data in file : $tmp");
		}
		$moved = rename($tmp, $path);
		$rights = chmod($path, 0600);
		return $moved && $rights;
	}

	/**
	 * Havelock constructor.
	 *
	 * @param string $password
	 * @param string $directory
	 * @param Cookie|null $cookie [optional]
	 * @return void
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

		$this->expire = self::DEFAULT_EXPIRE;

		$this->SodiumRegistry = new Sodium;
		$this->SodiumSession = new Sodium;
	}

	/**
	 * Session name
	 *
	 * @param string $name
	 * @return $this
	 */
	public function name(string $name): Havelock
	{
		$this->name = $name;
		return $this;
	}

	/**
	 * Cookie max lifetime
	 *
	 * @param int $seconds
	 * @return $this
	 */
	public function expire(int $seconds): Havelock
	{
		$this->expire = $seconds;
		return $this;
	}

	/**
	 * Set/unset registry keys in cookies
	 *
	 * @param bool $status [optional]
	 * @param Cookie|null $cookie [optional]
	 * @return $this
	 */
	public function cookie(bool $status = false, ? Cookie $cookie = null): Havelock
	{
		if($cookie) {
			$this->cookie = $cookie;
		}
		$this->useCookies = $status && $this->cookie;
		return $this;
	}

	/**
	 * Openssl random pseudo bytes length
	 *
	 * @param int $length [optional]
	 * @return $this
	 */
	public function randomLength(int $length = self::DEFAULT_SSL_RANDOM_LENGTH): Havelock
	{
		if($length >= self::DEFAULT_SSL_RANDOM_LENGTH) {
			$this->randomLength = $length;
		}
		return $this;
	}

	/**
	 * Number of keys / cookies required for bind and open session
	 *
	 * @param int $nb [optional]
	 * @return $this
	 */
	public function nbKeys(int $nb = self::DEFAULT_KEYS_NB): Havelock
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
	 * @return $this
	 */
	public function prefixKeys(string $name = self::DEFAULT_PREFIX_KEYS): Havelock
	{
		if($name) {
			$this->prefixKeys = $name;
		}
		return $this;
	}

	/**
	 * Expose/Inject registry keys
	 *
	 * @param array|null $keys
	 * @return array|string[]
	 */
	public function keys(array $keys = null): array
	{
		if(null === $keys) {
			return $this->keys;
		}
		if($keys) {
			foreach (range(1, $this->nbKeys) as $k) {
				$key = $this->prefixKeys . $k;
				if($registry = $keys[$key] ?? '') {
					$this->keys[$key] = $registry;
				}
			}
			if(count($this->keys) !== $this->nbKeys) {
				$this->keys = [];
				return [];
			}
			return $this->keys;
		}
		return [];
	}

	/**
	 * Generate customer session
	 *
	 * @return bool
	 * @throws Exception
	 */
	public function create(): bool
	{
		if(!$this->createSessionFile()) {
			return false;
		}
		if(!$this->createRegistyFiles()) {
			return false;
		}
		return true;
	}

	/**
	 * Refresh registry tokens
	 *
	 * @param bool $hard [optional]
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
		else {
			if(!$this->session || !$this->SodiumSession->getKeyPair() || !$this->SodiumRegistry->getKeyPair()) {
				return false;
			}
			$this->deleteRegistryFiles();
			return $this->createRegistyFiles();
		}
	}

	/**
	 * Try to load an existing session
	 *
	 * @return bool
	 * @throws SodiumException
	 */
	public function read(): bool
	{
		$this->data = null;

		if(!$this->loadKeys()) {
			return false;
		}

		if(!$this->initRegistryKeyPair()) {
			return false;
		}

		if(!$this->session || !$this->SodiumSession->getKeyPair()) {
			$raw = '';
			foreach ($this->keys as $registry) {
				$path = $this->registryDir . DIRECTORY_SEPARATOR . $registry;
				if(!is_file($path) || !($chunk = file_get_contents($path))) {
					return false;
				}
				$raw .= $chunk;
			}
			if($raw && $serialized = $this->SodiumRegistry->unseal($raw)) {
				$params = unserialize($serialized);
				if($id = $params['id'] ?? null) {
					$this->session = $id;
				}
				if($kp = $params['kp'] ?? null) {
					$kp = (string) base64_decode($kp);
					$this->SodiumSession->setKeyPair($kp);
				}
			}
		}

		$path = $this->sessionDir . DIRECTORY_SEPARATOR . $this->session;
		if($this->session && $this->SodiumSession->getKeyPair() && is_file($path)) {
			$raw = file_get_contents($path);
			if($raw && $serialized = $this->SodiumSession->unseal($raw)) {
				$this->data = unserialize($serialized);
			}
			elseif(false === $raw) {
				return false;
			}
			elseif(!$raw) {
				$this->data = [];
			}
		}
		else {
			return false;
		}

		return true;
	}

	/**
	 * Save data in current session.
	 *
	 * @param array|null $overwrite []
	 * @return bool
	 * @throws SodiumException
	 * @throws Exception
	 */
	public function save(? array $overwrite = null): bool
	{
		$path = $this->sessionDir . DIRECTORY_SEPARATOR . $this->session;
		if(!$this->session || !$this->SodiumSession->getKeyPair() || !is_file($path)) {
			return false;
		}
		if(null !== $overwrite) {
			$this->data = $overwrite;
		}
		$serialized = serialize($this->data);
		$encrypted = $this->SodiumSession->seal($serialized);
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
		return $this->data ?: [];
	}

	/**
	 * Entry exist in session data
	 *
	 * @param string $key
	 * @return bool
	 */
	public function exist(string $key): bool
	{
		return array_key_exists($key, $this->data);
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
	 * @return $this
	 */
	public function set(string $key, $value = null): Havelock
	{
		$this->data[$key] = $value;
		return $this;
	}

	/**
	 * Offload expired sessions.
	 *
	 * @param int $rand [optional]
	 * @param int|null $expire [optional]
	 * @return $this
	 */
	public function offload(int $rand = 0, ? int $expire = null): Havelock
	{
		if(!rand(0, abs($rand))) {
			$now = time();
			if(null === $expire) {
				$expire = $this->expire;
			}

			$registries = glob($this->registryDir . '/{,.}*', GLOB_BRACE) ?: [];
			$sessions = glob($this->sessionDir . '/{,.}*', GLOB_BRACE) ?: [];
			$files = array_merge($registries, $sessions);

			foreach($files as $file) {
				if(false === strpos($file, '.') && is_file($file)) {
					if ($now - filemtime($file) >= $expire) {
						unlink($file);
					}
				}
			}
		}
		return $this;
	}

	/**
	 * Destroy an existing customer session
	 *
	 * @return $this
	 * @throws SodiumException
	 */
	public function destroy(): Havelock
	{
		$sessions = $this->deleteRegistryFiles();
		$this->deleteSessionFile($sessions);

		$this->keys = [];
		$this->session = null;
		$this->SodiumSession->resetKeys();
		$this->data = null;
		return $this;
	}

	/**
	 * Init new empty registry and sessions.
	 *
	 * @return bool
	 * @throws SodiumException
	 */
	public function kill(): bool
	{
		$this->destroy();
		$this->SodiumRegistry->resetKeys();
		$rmdir = $this->rmdir();
		$mkdir = $this->mkdir();
		return $rmdir && $mkdir;
	}
}