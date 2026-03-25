<?php
class EncryptionHelper {
    private $method = 'AES-256-CBC';
    
    public function generateKey() {
        return bin2hex(openssl_random_pseudo_bytes(32));
    }
    
    public function encrypt($data, $key) {
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->method));
        $encrypted = openssl_encrypt($data, $this->method, hex2bin($key), 0, $iv);
        
        return [
            'data' => base64_encode($encrypted),
            'iv' => base64_encode($iv)
        ];
    }
    
    public function decrypt($encryptedData, $key, $iv) {
        return openssl_decrypt(
            base64_decode($encryptedData),
            $this->method,
            hex2bin($key),
            0,
            base64_decode($iv)
        );
    }
}
?>