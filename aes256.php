<?php

/**
 * AES-256 cipher.
 * @uses mcrypt PHP Mcrypt extension needs to be enabled.
 */
class Aes256 {
    
    private $securekey;
    private $iv;
    
    function __construct($textkey) {
        $this->securekey = hash('sha256', $textkey, TRUE);
        $this->iv = mcrypt_create_iv(32);
    }
    
    /**
     * Encrypt the clear text.
     * @param type $clearText
     * @return type
     */
    public function encrypt($clearText) {
        return base64_encode(mcrypt_encrypt(
                MCRYPT_RIJNDAEL_256, 
                $this->securekey, 
                $clearText, 
                MCRYPT_MODE_ECB, 
                $this->iv
        ));
    }
    
    /**
     * Decrypt the crypt text.
     * @param type $cryptText
     * @return type
     */
    public function decrypt($cryptText) {
        return trim(mcrypt_decrypt(
                MCRYPT_RIJNDAEL_256, 
                $this->securekey, 
                base64_decode($cryptText), 
                MCRYPT_MODE_ECB, 
                $this->iv
        ));
    }
}
