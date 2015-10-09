<?php
namespace Cigital\Safetynet;

class MockSession extends Session
{
    protected $keys = [];

    public function __construct()
    {

    }

    public function store($key, $value)
    {
        $this->keys[$key] = $value;
    }

    public function get($key)
    {
        return $this->keys[$key];
    }
}
