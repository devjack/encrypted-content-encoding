# Encrypted Content-Encoding

## Introduction

> PHP implementation of [RFC8188](https://tools.ietf.org/html/rfc8188) to encrypt HTTP messages.

[![Build Status](https://travis-ci.org/devjack/encrypted-content-encoding.svg?branch=master)](https://travis-ci.org/devjack/encrypted-content-encoding)
[![Latest Stable Version](https://poser.pugx.org/devjack/encrypted-content-encoding/v/stable)](https://packagist.org/packages/devjack/encrypted-content-encoding)
[![Total Downloads](https://poser.pugx.org/devjack/encrypted-content-encoding/downloads)](https://packagist.org/packages/devjack/encrypted-content-encoding)
[![Latest Unstable Version](https://poser.pugx.org/devjack/encrypted-content-encoding/v/unstable)](https://packagist.org/packages/devjack/encrypted-content-encoding)
[![License](https://poser.pugx.org/devjack/encrypted-content-encoding/license)](https://packagist.org/packages/devjack/encrypted-content-encoding)

## Code Samples

> Note: RFC8188 relies heavily on Base64URL encoding. A static encode/decode function is available for convenience.

```php
require_once "vendor/autoload.php";

use DevJack\EncryptedContentEncoding\RFC8188;
use DevJack\EncryptedContentEncoding\SimpleKeyProvider;

$keyProvider = new SimpleKeyProvider(
    ['sample-key-id' => RFC8188::base64url_decode('yqdlZ-tYemfogSmv7Ws5PQ')]
);

$rfc8188 = new RFC8188(
    $keyProvider, // Instance of class that implements KeyProviderInterface
    4096, // Optional default record size. If not provided, must be called with encode()
    'defauly-key-id' // Optional default key id. If not provided, must be called with encode()
);

$message = "I Am the walrus";

$encoded = $rfc8188->encode($message, 'sample-key-id', 4096);
$decoded = $rfc8188->decode($encoded);
```

## Installation

```
composer require devjack/encrypted-content-encoding
```
