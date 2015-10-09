<?php

class PayloadValidatorTest extends PHPUnit_Framework_TestCase
{
    public function testValidate()
    {
        $session = new \Cigital\Safetynet\MockSession();

        // The values "generated" by /getnonce
        $session->store('nonce', 'Qm93RGdQY3o4VEhPYjFlVUpaMDJGdUxmRkNaUFZEWVYyWEppQm54TTZvbz0');
        $session->store('nonce_timestamp', 1443011990950 / 1000);

        // The values we will be expecting (settings per web service)
        $validator = new \Cigital\Safetynet\PayloadValidator(
            $session,
            "com.cigital.safetynetplayground",
            "3F745359AF412C424B3832846B4F4AF82ED878B28B0B0CFA8E429458A2F708E6",
            "3bfca6699111810b8e8411d66518f50296f1e998175468892c31d07beeec837a"
        );

        // JWS Payload content
        $result = $validator->validate(
            array(
                'nonce'                      => 'Qm93RGdQY3o4VEhPYjFlVUpaMDJGdUxmRkNaUFZEWVYyWEppQm54TTZvbz0=',
                'timestampMs'                => 1443011990951,
                'apkPackageName'             => 'com.cigital.safetynetplayground',
                'apkDigestSha256'            => 'O/ymaZERgQuOhBHWZRj1Apbx6ZgXVGiJLDHQe+7sg3o=',
                'ctsProfileMatch'            => true,
                'extension'                  => 'CaHFPGuPgOZJ',
                'apkCertificateDigestSha256' =>
                    array(
                        0 => 'P3RTWa9BLEJLODKEa09K+C7YeLKLCwz6jkKUWKL3COY=',
                    ),
            )
        );

        $this->assertTrue($result);
    }
}
