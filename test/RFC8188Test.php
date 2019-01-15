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
            function($keyid) { return b64::decode("yqdlZ-tYemfogSmv7Ws5PQ"); }
        );

        $this->assertEquals("I am the walrus", $decoded);
    }

    public function testDecryptRFC8188Example32(): void 
    {
        $encoded = b64::decode("uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA");
        
        $decoded = RFC8188::rfc8188_decode(
            $encoded, // data to decode 
            function($keyid) { return b64::decode("BO3ZVPxUlnLORbVGMpbT1Q"); }
        );

        $this->assertEquals("I am the walrus", $decoded);
    }

    public function testIAmTheWalrus(): void
    {
        $message = "I am the walrus";

        $encoded = RFC8188::rfc8188_encode(
            $message, // plaintext
            b64::decode("yqdlZ-tYemfogSmv7Ws5PQ"), // encryption key
            null,   // key ID
            132    // record size.
        );
        $decoded = RFC8188::rfc8188_decode(
            $encoded, // data to decode 
            function($keyid) { return b64::decode('yqdlZ-tYemfogSmv7Ws5PQ'); }
        );

        $this->assertEquals($message, $decoded);
    }


    public function testMultiRecordParagraphs(): void
    {
        $key = \random_bytes(16);

        $message = "I am the egg man
        They are the egg men
        I am the walrus
        Goo goo g'joob, goo goo goo g'joob
        Goo goo g'joob, goo goo goo g'joob, goo goo";

        $encoded = RFC8188::rfc8188_encode(
            $message, // plaintext
            $key, // encryption key
            $key,
            30    // record size.
        );
        $decoded = RFC8188::rfc8188_decode(
            $encoded, // data to decode 
            function($keyid ) use ($key) { return $key; }
        );

        $this->assertEquals($message, $decoded);
    }
}