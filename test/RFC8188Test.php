<?php
declare(strict_types=1);
namespace DevJack\EncryptedContentEncoding\Test;

use PHPUnit\Framework\TestCase;

use DevJack\EncryptedContentEncoding\RFC8188;
use Base64Url\Base64Url as b64;

final class RFC8188Test extends TestCase
{

    public function testDecryptRFC8188Example31(): void
    {
        $encoded = b64::decode("I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg");
        
        $decoded = RFC8188::rfc8188_decode(
            $encoded, // data to decode 
            [b64::decode("yqdlZ-tYemfogSmv7Ws5PQ")] // Keys
        );

        $this->assertEquals("I am the walrus", $decoded);
    }

    public function testIAmTheWalrus(): void
    {
        $keys = [
            b64::decode('yqdlZ-tYemfogSmv7Ws5PQ'),
        ];
        $message = "I am the walrus";

        $encoded = RFC8188::rfc8188_encode(
            $message, // plaintext
            b64::decode("yqdlZ-tYemfogSmv7Ws5PQ"), // encryption key
            null,   // key ID
            132    // record size.
        );
        $decoded = RFC8188::rfc8188_decode(
            $encoded, // data to decode 
            [b64::decode("yqdlZ-tYemfogSmv7Ws5PQ")] // Keys
        );

        $this->assertEquals($message, $decoded);
    }
}