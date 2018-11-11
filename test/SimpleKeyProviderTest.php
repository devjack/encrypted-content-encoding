<?php
declare(strict_types=1);
namespace DevJack\EncryptedContentEncoding\Test;

use PHPUnit\Framework\TestCase;

use DevJack\EncryptedContentEncoding\RFC8188;
use DevJack\EncryptedContentEncoding\SimpleKeyProvider;
use DevJack\EncryptedContentEncoding\Exception\EncryptionKeyNotFound;
use Base64Url\Base64Url as b64;

final class SimpleKeyProviderTest extends TestCase
{
    public function testThrowsKeyNotFound() {
        $keyProvider = new SimpleKeyProvider(
            ['sample-key-id' => RFC8188::base64url_decode('yqdlZ-tYemfogSmv7Ws5PQ')]
        );

        $this->expectException(EncryptionKeyNotFound::class);
        $keyProvider->getKey('different-key');
    }

    public function testProvidesKey() {
        $keyProvider = new SimpleKeyProvider(
            ['sample-key-id' => "foobar"]
        );
        $this->assertEquals("foobar", $keyProvider->getKey('sample-key-id'));
    }

}
