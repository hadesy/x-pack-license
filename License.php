<?php


/**
 * Class License
 * Only Support License V4
 */
class License
{

    const X_PACK_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuNN9c95+ghKiFYiXb3j2
I9g8lytA1i7GyHrQEXLUfO5M5W85ojsZQdYCQRSbssIDcQbGxs6QWriKuuFBMqI3
bppRpYh1sQFvRY+cwCknq+aPWDpgStRXWTFUthNOrCUUvhEVixCMDF4yfQArKw5Y
+FBCjiRdJ+HoV9riMcLWUBbtlVPsfkKoIPrcvLZVcozNECFYJ+Wik15Zl27CgQwf
ex/XYbZi2l19PQQ+w+N1ovO2aOMmrpo1gHGt+1NyQ8Pfh8De+wcxIWJU1OwdijXP
aeYXgO3OOhrD8MwRqW/fh126ffS/pISKMMMTw3s68mCWcc7KNkiqATKCOH/WS0B1
VwIDAQAB
-----END PUBLIC KEY-----';

    const YOUR_PUBLIC_KEY = '';

    const YOUR_PRIVATE_KEY = '';

    /**
     * @param string $license
     * @return bool
     */
    public static function verify(string $license)
    {
        $jsonData = json_decode($license, true);
        $license = $jsonData['license'];

        $signatureBytes = base64_decode($license['signature']);
        $version = self::getInt($signatureBytes, 0, 4);
        $magicLen = self::getInt($signatureBytes, 4, 4);
        $hashLen = self::getInt($signatureBytes, 8 + $magicLen, 4);
        $signedContentLen = self::getInt($signatureBytes, 12 + $magicLen + $hashLen, 4);
        $signedContent = substr($signatureBytes, 16 + $magicLen + $hashLen, $signedContentLen);
        unset($license['signature']);
        return openssl_verify(json_encode($license), $signedContent, self::YOUR_PUBLIC_KEY, OPENSSL_ALGO_SHA512);
    }


    /**
     * @param string $license
     * @return string
     * @throws Exception
     */
    public static function sign(string $license)
    {

        openssl_sign($license, $signedContent, self::YOUR_PRIVATE_KEY, OPENSSL_ALGO_SHA512);

        $byteBuffer = '';
        $byteBuffer .= pack("N", 4);
        $byteBuffer .= pack("N", 13);
        $byteBuffer .= random_bytes(13);
        $byteBuffer .= pack("N", 408);
        //PEB Encryption Not Implemented
        $byteBuffer .= random_bytes(408);
        $byteBuffer .= pack("N", strlen($signedContent));
        $byteBuffer .= $signedContent;

        $licenseArray = json_decode($license, true);
        $licenseArray['signature'] = base64_encode($byteBuffer);

        return json_encode(['license' => $licenseArray],JSON_UNESCAPED_SLASHES);
    }


    static function getInt($bytes, $offset, $length)
    {
        return current(unpack("N", substr($bytes, $offset, $length)));
    }

}
