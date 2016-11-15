<?php

class NoncerTest extends PHPUnit_Framework_TestCase
{
    public function testGenerate()
    {
        $session = new \Cigital\Safetynet\Session();
        $noncer = new \Cigital\Safetynet\Noncer($session);

        $nonce = $noncer->generate();

        $this->assertTrue((base64_encode(base64_decode($nonce, true)) === $nonce));
    }
}
