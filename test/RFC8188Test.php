<?php
namespace DevJack\EncryptedContentEncoding\Test;

use PHPUnit\Framework\TestCase;

use DevJack\EncryptedContentEncoding\RFC8188;
use DevJack\EncryptedContentEncoding\Test\Mock\MockKeyLookupProvider;
use DevJack\EncryptedContentEncoding\Exception\EncryptionKeyNotFound;
use Base64Url\Base64Url as b64;

final class RFC8188Test extends TestCase
{

    public function testDecryptRFC8188Example31()
    {
        $encoded = b64::decode("I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg");
        
        $decoded = RFC8188::rfc8188_decode(
            $encoded, // data to decode 
            function($keyid) { return b64::decode("yqdlZ-tYemfogSmv7Ws5PQ"); }
        );

        $this->assertEquals("I am the walrus", $decoded);
    }

    public function testDecryptRFC8188Example32()
    {
        $encoded = b64::decode("uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA");
        
        $decoded = RFC8188::rfc8188_decode(
            $encoded, // data to decode 
            function($keyid) { return b64::decode("BO3ZVPxUlnLORbVGMpbT1Q"); }
        );

        $this->assertEquals("I am the walrus", $decoded);
    }

    public function testIAmTheWalrus()
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


    public function testMultiRecordParagraphs()
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

    public function testCanInvokeCallableClassAsKeyProvider() {
        $encoded = b64::decode("uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA");
        $keyProvider = new MockKeyLookupProvider();
        $keyProvider->addKey(b64::decode("BO3ZVPxUlnLORbVGMpbT1Q"), 'a1');
        $decoded = RFC8188::rfc8188_decode(
            $encoded, // data to decode 
            $keyProvider
        );

        $this->assertEquals("I am the walrus", $decoded);
    }

    public function testMockLookupProviderThrowsKeyNotFoundException() {
        $encoded = b64::decode("uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA");
        
        $keyProvider = new MockKeyLookupProvider();
        $keyProvider->addKey(b64::decode("BO3ZVPxUlnLORbVGMpbT1Q"), ''); // intentionally set keyid NOT to 'a1'
        
        $this->expectException(EncryptionKeyNotFound::class);
        
        $decoded = RFC8188::rfc8188_decode(
            $encoded, // data to decode 
            $keyProvider
        );
    }

    /**
     * @requires PHP 5.6
     */
    public function testCanPHP56DecodePHP71EncodedContent() {

        // Encoded using PHP 7.2.9
        $encoded = b64::decode("Nviu8NbdiSGm-tFxx1-2-gAAAIQAWoS9c1AaFoN_B_EXtQnnpaNWsADFk_inb1ijxvNouLM");
        $decoded = RFC8188::rfc8188_decode(
            $encoded, // data to decode 
            function($keyid ) { return b64::decode("yqdlZ-tYemfogSmv7Ws5PQ"); }
        );
        $this->assertEquals("I am the walrus", $decoded);
    }

    /**
     * @requires PHP 7.0
     */
    public function testCanPHP7xDecodePHP56EncodedContent() {

        // Encoded using PHP 7.2.9
        $encoded = b64::decode("SCzPAGhMcr2rHMPIS5iszgAAAIQA-FA0NUiBf4x6opiYp6x8QjJSuRF6l71uqaT_CbSkXiY");
        $decoded = RFC8188::rfc8188_decode(
            $encoded, // data to decode 
            function($keyid ) { return b64::decode("yqdlZ-tYemfogSmv7Ws5PQ"); }
        );
        $this->assertEquals("I am the walrus", $decoded);
    }
}