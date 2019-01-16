<?php

namespace DevJack\EncryptedContentEncoding;

interface EncryptionKeyProviderInterface {
    /*
     * EncryptionKeyProvider's must be invokable.
     */
    public function __invoke($keyid);
}