# Coercive Havelock

Experimental project: encrypted serialized data.

## Get

```
composer require coercive/havelock
```

## Usage

```php
use Coercive\Security\Cookie\Cookie;
use Coercive\Security\Havelock\Havelock;

# Example of loading class Cookie
$crypt = 'exampleAbCdE12345';
$salt = 'example123';
$prefix = 'example_';
$cookie = (new Cookie($crypt, '/', '.domain.com', true, true))
                ->anonymize(true, $salt, $prefix);

# Example of loading class Havelock
$crypt = 'example1234567890ABCDEF';
$dir = '/www/secure/directory/havelock';
$havelock = new Havelock($crypt, $dir, $cookie);

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# For the first time, the internal directories must be created
# You can use the absolute reinit function :
$havelock->kill();

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Initialize Havelock for the current user
$havelock->create();

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Load session and show data
$havelock->read();
var_dump($havelock->data());
var_dump($havelock->get('user'));
var_dump($havelock->get('token'));
var_dump($havelock->get('test'));

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Save data
$havelock->save([
    'user' => 123,
    'token' => 456,
    'test' => 'hello',
]);

# Or
$havelock->data([
    'user' => 123,
    'token' => 456,
    'test' => 'hello',
]);
$havelock->save();

# Or
$havelock->set('user', 123);
$havelock->set('token', 456);
$havelock->set('test', 'hello');
$havelock->save();

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# If you do not use cookie, you can store registry keys elsewhere

# First, disable cookie
$havelock = new Havelock($crypt, $dir /* not insert Cookie class here */);
# OR
$havelock->cookie(false);

# Inject external registry keys
$keys = [
    'TEST_KEY_1' => 'xxxxxxxxxx',
    'TEST_KEY_2' => 'yyyyyyyyyy',
    'TEST_KEY_3' => 'zzzzzzzzzz'
];

$havelock->prefixKeys('TEST_KEY_');
$havelock->keys($keys);

# Expose internal registry keys
$keys = $havelock->keys();

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Refresh regstry tokens and cookies
$havelock->refresh();

# Delete current user session
$havelock->destroy();

# Delete all expired session
$havelock->offload();

```
