<?php
namespace DevJack\EncryptedContentEncoding;

use Base64Url\Base64Url as b64;

class RFC8188
{
    protected static function hkdf($salt, $ikm, $sequence=0)
    {
        $prk = hash_hmac('sha256', $ikm, $salt, true);
        $cek_info = "Content-Encoding: aes128gcm\x00";
        $cek = substr(hash_hmac("sha256", "$cek_info\x01", $prk, true), 0, 16);
    
        $nonce_info = "Content-Encoding: nonce\x00";
        $seq =  pack("NNN", 0x00, 0x00, $sequence); //todo pack this properly to 96-bits
        $nonce = hash_hmac("sha256", "$nonce_info\x01", $prk, true) ^ $seq;
    
        return [
            "cek" => $cek,
            "nonce" => $nonce,
        ];
    }

    public static function rfc8188_decode($payload, $key_lookup)
    {       
        if (!is_callable($key_lookup)) {
            throw new Exception(sprintf(
                '$key_lookup must be invocable'
            ));
        }

        $payload_hex = bin2hex($payload);
        $salt = hex2bin(substr($payload_hex, 0, 16*2));
        $rs = hexdec(substr($payload_hex, 32, 4*2));
        $idlen = hexdec(substr($payload_hex, 40, 1*2));
        $header_boundary = 42 + $idlen*2;
        $keyid = hex2bin(substr($payload_hex, 42, $idlen*2));
        
        $key = $key_lookup($keyid);
        
        if(is_null($key)) {
            throw new \Exception(sprintf(
                'Key lookup returned in invalid key'
            ));
        }
        
        $encoded_body = substr($payload_hex, $header_boundary);
    
        $records = str_split($encoded_body, ($rs*2));

        $return = "";
        
        // decrypt each record
        for ($s=0; $s<count($records); $s++) {
            $r = hex2bin($records[$s]);
            $ciphertext = substr($r, 0, strlen($r)-16);
            $tag = substr($r, strlen($r)-16);
    
            $hkdf = self::hkdf($salt, $key, $s);

            // decrypt
            $decrypted_record = openssl_decrypt($ciphertext, "aes-128-gcm", $hkdf['cek'], OPENSSL_RAW_DATA, $hkdf['nonce'], $tag);
            if (false === $decrypted_record) {
                throw new \Exception(sprintf(
                    "OpenSSL error: %s",
                    openssl_error_string()
                ));
            }

            // remove 0x00 padding
            $decrypted_record = rtrim($decrypted_record, "\x00");
            if(substr($decrypted_record, -1) == "\x01") {
                // Normal recode deliminter
                $return .= rtrim($decrypted_record, "\x01"); // remove the 0x01 and return
            } else if(substr($decrypted_record, -1) == "\x02") {
                if ($s !== count($records)-1) {
                    throw new \Exception("Invalid encoding. 0x02");
                }
                $return .= rtrim($decrypted_record, "\x02"); // remove the 0x01 and return
            } else {
                throw new \Exception("Invalid encoding. No record delimiter.");
            }
        }
        
        return $return;
    }

    public static function rfc8188_encode($payload, $key, $keyid=null, $rs=25)
    {
        // Calculate header:
        $salt = random_bytes(16);
        $header = bin2hex($salt)
            .(sprintf('%08X', $rs))
            .bin2hex(pack("C", strlen($keyid)))
            .bin2hex($keyid);
        $header = hex2bin($header);

        $return = $header; // $header is the first chunk of the return body

        $plaintext_records = str_split($payload, $rs-17);
        // Process records
        $number_of_records = count($plaintext_records);
        for ($p=0; $p<count($plaintext_records); $p++) {
            
            $plaintext_record = $plaintext_records[$p];
            
            if ($p == $number_of_records - 1) {
                // 0x02 delimits padding in the last record
                $plaintext_record = $plaintext_record."\x02";
            } else {
                // 0x01 delimits padding in each record
                $plaintext_record = str_pad($plaintext_record."\x01", $rs-16, "\x00", STR_PAD_RIGHT);
            }

            $hkdf = self::hkdf($salt, $key, $p);

            $encrypted = openssl_encrypt($plaintext_record, "aes-128-gcm", $hkdf['cek'], OPENSSL_RAW_DATA, $hkdf['nonce'], $tag);
        
            if (false === $encrypted) {
                throw new Exception(sprintf(
                    "OpenSSL error: %s", openssl_error_string()
                ));
            }
            $block = $encrypted.$tag;
            $return .= $block;
        }
        return $return;
    }
}
