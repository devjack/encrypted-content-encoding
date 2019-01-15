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
            $key = array_pop($keys);
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

            // Check for the padding delim and remove it.
            for ($i=strlen($decrypted_record); $i>0; $i--) {
                $byte = bin2hex(substr($decrypted_record, $i-1, 1));
                
                if ($byte === 0x00) {
                    continue;
                } elseif ($byte == 0x02) {
                    // 0x02 is only used for the last record
                    if ($s !== count($records)-1) {
                        throw new \Exception("Invalid encoding. 0x02");
                    }
                    // Slice off the padding.
                    $unpadded_record = substr($decrypted_record, 0, strlen($decrypted_record)-$i-1);
                    $return .= $unpadded_record;
                } elseif ($byte == 0x01) {
                    // Found a 0x01 delimiter. Slice off the padding.
                    $unpadded_record = substr($decrypted_record, 0, strlen($decrypted_record)-$i-1);
                    $return .= $unpadded_record;
                }
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

        $plaintext_records = str_split($payload, $rs-16);
        // Process records
        $number_of_records = count($plaintext_records);
        for ($p=0; $p<count($plaintext_records); $p++) {
            // For each 'page' in the payload, create and encrypt a record.
            if ($p == $number_of_records - 1) {
                // last page, take the remaining plaintext with 0x02
                $record_plaintext = substr($payload, $p*($rs-16))."\x02";    
            } else {
                // 0x01 delimits padding in each record
                $record_plaintext = substr($payload, $p*($rs-16), $rs)."\0x01";
                $record_plaintext = str_pad($record_plaintext, $rs, "\x00", STR_PAD_RIGHT);
            }

            $hkdf = self::hkdf($salt, $key, $p);

            $encrypted = openssl_encrypt($record_plaintext, "aes-128-gcm", $hkdf['cek'], OPENSSL_RAW_DATA, $hkdf['nonce'], $tag);
        
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
