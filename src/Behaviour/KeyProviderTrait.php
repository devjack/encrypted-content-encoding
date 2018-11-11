<?php
namespace DevJack\EncryptedContentEncoding\Behaviour;

use Base64Url\Base64Url as b64;
use DevJack\EncryptedContentEncoding\Exception\EncryptionKeyNotFound;

trait KeyProviderTrait {
    
    protected $keys = [];

    public function getKey(string $id) : string {
        if (array_key_exists($id, $this->keys)) {
            return $this->keys[$id];
        }
        throw new EncryptionKeyNotFound("Key $id is not configured.");
    }
    
}