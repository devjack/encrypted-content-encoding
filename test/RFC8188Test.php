<?php
declare(strict_types=1);
namespace DevJack\EncryptedContentEncoding\Test;

use PHPUnit\Framework\TestCase;

use DevJack\EncryptedContentEncoding\RFC8188;
use Base64Url\Base64Url as b64;

final class RFC8188Test extends TestCase
{
    public function testIAmTheWalrus(): void
    {
        $keys = [
            b64::decode('yqdlZ-tYemfogSmv7Ws5PQ'),
        ];
        $message = "I Am the walrus";

        $encoded = RFC8188::rfc8188_encode(
            $message, // plaintext
            b64::decode("yqdlZ-tYemfogSmv7Ws5PQ"), // encryption key
            null,   // key ID
            4096    // record size.
        );
        $decoded = RFC8188::rfc8188_decode(
            $encoded, // data to decode 
            [b64::decode("yqdlZ-tYemfogSmv7Ws5PQ")] // Keys
        );

        $this->assertEquals($message, $decoded);
    }
}