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

    public static function rfc8188_decode($payload, $keys = [])
    {       
        if (empty($keys)) {
            throw new Exception(sprintf(
                "Decryption keys not provided"
            ));
        }

        $payload_hex = bin2hex($payload);
        $salt = hex2bin(substr($payload_hex, 0, 16*2));
        $rs = hexdec(substr($payload_hex, 32, 4*2));
        $idlen = hexdec(substr($payload_hex, 40, 1*2));
        $header_boundary = 42 + $idlen*2;
        $keyid = hex2bin(substr($payload_hex, 42, $idlen*2));
    
        if ($keyid) {
            $key = $keys[$keyid];
        } else {
            // If the key ID is not provided, then attempt using the first and likely only key.
            $key = $keys[0];
        }
        
        $encoded_body = substr($payload_hex, $header_boundary);
    
        $records = str_split($encoded_body, ($rs*2));
    
        $return = "";
        // decrypt each record
        for ($s=0; $s<count($records); $s++) {
            $r = hex2bin($records[$s]);
            
            // // check and fail for no non-zero octet
            // for($i=0; $i<strlen($r)/2; $i++){
            //     $octet = substr($r, $i, $i+1);
            //     if(hexdec($octet) != 0x00) {
            //         break; // non-zero octet, no failure, break check and continue
            //     }
            // }
    
            // // check and fail if the last record contains padding other than 0x02
            // if (count($records)-1 == $s) {
            //     // This is the last record
            //     $padding_delim = substr($r, -34, 2);
            //     if(hexdec($padding_delim) != 0x2) {
            //         echo "EXPECTED 0x02 AS PADDING DELIM";
            //     }
            // }
    
            $block = substr($r, 0, strlen($r)-16);
            $tag = substr($r, strlen($r)-16);
    
            $hkdf = self::hkdf($salt, $key, $s);

            // decrypt
            $decrypted_record = openssl_decrypt($block, "aes-128-gcm", $hkdf['cek'], OPENSSL_RAW_DATA, $hkdf['nonce'], $tag);
            if (false === $decrypted_record) {
                throw new Exception(sprintf(
                    "OpenSSL error: %s", openssl_error_string()
                ));
            }
            $return .= $decrypted_record;
            
            // todo check and fail if the record isn't last and isn't padded with 0x1
        }

        return $decrypted_record;
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

        // Process records
        $pages = ceil(strlen($payload) / ($rs-17));

        for ($p=0; $p<$pages; $p++) {
            // For each 'page' in the payload, create and encrypt a record.
            if ($p == $pages - 1) {
                // last page, take the remaining plaintext
                $record_plaintext = substr($payload, $p*$rs)."\x02";
            } else {
                $record_plaintext = substr($payload, $p*$rs, $rs)."\0x01";
                $record_plaintext = str_pad($record_plaintext, $rs, "\x00", STR_PAD_RIGHT);
            }

            $hkdf = self::hkdf($salt, $key, $p);

            $encrypted = openssl_encrypt($payload, "aes-128-gcm", $hkdf['cek'], OPENSSL_RAW_DATA, $hkdf['nonce'], $tag);
        
            if (false === $encrypted) {
                throw new Exception(sprintf(
                    "OpenSSL error: %s", openssl_error_string()
                ));
            }
            $return .= $encrypted.$tag;
        }
        return $return;
    }
}
