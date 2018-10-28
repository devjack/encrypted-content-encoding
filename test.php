<?php
require_once "vendor/autoload.php";
use DevJack\EncryptedContentEncoding\RFC8188;
use Base64Url\Base64Url as b64;

$keys = [
    b64::decode('yqdlZ-tYemfogSmv7Ws5PQ'),
    "a1" => b64::decode('BO3ZVPxUlnLORbVGMpbT1Q'),
];

$message = "I Am the walrus";
$encoded = RFC8188::rfc8188_encode(
    $message, // plaintext
    b64::decode("yqdlZ-tYemfogSmv7Ws5PQ"), // encryption key
    null,   // key ID
    4096    // record size.
);
echo "E => ".b64::encode($encoded).PHP_EOL;
$decoded = RFC8188::rfc8188_decode(
    $encoded, // data to decode 
    [b64::decode("yqdlZ-tYemfogSmv7Ws5PQ")] // Keys
);
echo "P => ". $decoded .PHP_EOL;

echo "Encoding/decoding successful?? ". ($message === $decoded).PHP_EOL;