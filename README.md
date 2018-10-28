# Encrypted Content-Encoding

## Introduction

> PHP implementation of RFC8188 to encrypt HTTP messages.

## Code Samples

> Note: RFC8188 relies heavily on base64 URL encoding. 

```php
require_once "vendor/autoload.php";

use Base64Url\Base64Url as b64;

$encoded = RFC8188::rfc8188_encode(
    "I am the walrus", // plaintext
    b64::decode("yqdlZ-tYemfogSmv7Ws5PQ"), // encryption key
    null,   // key ID
    4096    // record size. Default is 25
);

$decoded = RFC8188::rfc8188_decode(
    $encoded, // data to decode 
    [b64::decode("yqdlZ-tYemfogSmv7Ws5PQ")] // Keys
);

echo "Encrypted === Decrypted? " .($decoded === "I am the walrus");
```



## Installation

```
composer require devjack/encrypted-content-encoding
```
