<?php
declare(strict_types=1);
namespace DevJack\EncryptedContentEncoding\Test;

use PHPUnit\Framework\TestCase;

use DevJack\EncryptedContentEncoding\RFC8188;
use DevJack\EncryptedContentEncoding\SimpleKeyProvider;
use Base64Url\Base64Url as b64;

final class RFC8188Test extends TestCase
{
    public function testIAmTheWalrus(): void
    {
        $keyProvider = new SimpleKeyProvider(
            ['sample-key-id' => RFC8188::base64url_decode('yqdlZ-tYemfogSmv7Ws5PQ')]
        );

        $rfc8188 = new RFC8188(
            $keyProvider, // Instance of class that implements KeyProviderInterface
            4096 // default record size
        );

        $message = "I Am the walrus";

        $encoded = $rfc8188->encode($message, 'sample-key-id', 4096);
        $decoded = $rfc8188->decode($encoded);

        $this->assertEquals($message, $decoded);
    }
}
