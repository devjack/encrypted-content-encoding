<?php
namespace DevJack\EncryptedContentEncoding;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Base64Url\Base64Url as b64;
use DevJack\EncryptedContentEncoding\Behaviour\KeyProviderTrait;
use DevJack\EncryptedContentEncoding\KeyProviderInterface;

class SimpleKeyProvider implements KeyProviderInterface
{
    use KeyProviderTrait;

    public function __construct(array $keys) {
        $this->keys = $keys;
    }
}
