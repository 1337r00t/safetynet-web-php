<?php

class NoncerTest extends PHPUnit_Framework_TestCase
{
    public function testGenerate()
    {
        $noncer = new \Cigital\Safetynet\Noncer();

        $nonce = $noncer->generate();

        $this->assertTrue((base64_encode(base64_decode($nonce, true)) === $nonce));
    }
}
