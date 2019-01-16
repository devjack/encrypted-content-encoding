# Encrypted Content-Encoding

## Introduction

> PHP implementation of RFC8188 to encrypt HTTP messages.

[![Build Status](https://travis-ci.org/devjack/encrypted-content-encoding.svg?branch=master)](https://travis-ci.org/devjack/encrypted-content-encoding)
[![Latest Stable Version](https://poser.pugx.org/devjack/encrypted-content-encoding/v/stable)](https://packagist.org/packages/devjack/encrypted-content-encoding)
[![Total Downloads](https://poser.pugx.org/devjack/encrypted-content-encoding/downloads)](https://packagist.org/packages/devjack/encrypted-content-encoding)
[![Latest Unstable Version](https://poser.pugx.org/devjack/encrypted-content-encoding/v/unstable)](https://packagist.org/packages/devjack/encrypted-content-encoding)
[![License](https://poser.pugx.org/devjack/encrypted-content-encoding/license)](https://packagist.org/packages/devjack/encrypted-content-encoding)

## Code Samples

> Note: RFC8188 relies heavily on base64 URL encoding. 

### Simple callback function for encryption key lookup

```php
require_once "vendor/autoload.php";

use Base64Url\Base64Url as b64;

$message = "I am the walrus";

$encoded = RFC8188::rfc8188_encode(
    $message, // plaintext
    b64::decode("yqdlZ-tYemfogSmv7Ws5PQ"), // encryption key
    null,   // key ID
    123    // record size.
);
$decoded = RFC8188::rfc8188_decode(
    $encoded, // data to decode 
    function($keyid) { return b64::decode('yqdlZ-tYemfogSmv7Ws5PQ'); }
);

$this->assertEquals($message, $decoded);
```

### Invocable class for key lookup
In this example we use a simple incovable class to provide key lookup. This may be more useful in complex framework integrations such as providing middleware that looks up keys from a database. This sample does not cover service injection to the key lookup class.

```php
use DevJack\EncryptedContentEncoding\RFC8188;
use DevJack\EncryptedContentEncoding\Exception\EncryptionKeyNotFound;
use Base64Url\Base64Url as b64;

class MockKeyLookupProvider {

    protected $keys = [];

    public function addKey($key, $keyid='') {
        $this->keys[$keyid] = $key;
    }
    public function __invoke($keyid) {
        if (in_array($keyid, array_keys($this->keys))) {
            return $this->keys[$keyid];
        }
        throw new EncryptionKeyNotFound("Encryption key not found.");
    }
}


$encoded = b64::decode("uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA");

$keyProvider = new MockKeyLookupProvider();
$keyProvider->addKey(b64::decode("BO3ZVPxUlnLORbVGMpbT1Q"), 'a1');

$decoded = RFC8188::rfc8188_decode(
    $encoded, // data to decode
    $keyProvider
);
```

## Installation

Available via composer.

```
composer require devjack/encrypted-content-encoding
```

### PHP 5.6 compatibility
Additionally, install a polyfill for random_bytes such as:

```
composer require paragonie/random_compat
```

