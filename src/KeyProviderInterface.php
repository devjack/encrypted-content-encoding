<?php
namespace DevJack\EncryptedContentEncoding;

use Base64Url\Base64Url as b64;

interface KeyProviderInterface {
    /**
     * Return a b64 encoded encryption key given the $id provided
     */
    public function getKey(string $id) : string;
}