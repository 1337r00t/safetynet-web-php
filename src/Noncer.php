<?php
namespace Cigital\Safetynet;

class Noncer
{
    /** @var Session $session */
    protected $session;

    /**
     * Noncer constructor.
     *
     * @param Session $session
     */
    public function __construct(Session $session)
    {
        $this->session = $session;
    }

    /**
     * In this case we behave as if only one device ever uses the service, in reality you want to id every device and their nonces.
     *
     * @param string $nonce
     */
    public function store($nonce)
    {
        // store this in a database or something
        // here we are just going to create a nonce.txt file to hold the only the last generated nonce
        $this->session->store('nonce', $nonce);
        $this->session->store('nonce_timestamp', microtime(true));
    }

    /**
     * @return string
     */
    public function generate()
    {
        // generates a new nonce, use whatever lib you like

        $nonce = base64_encode(openssl_random_pseudo_bytes(32));

        return $nonce;
    }
}
