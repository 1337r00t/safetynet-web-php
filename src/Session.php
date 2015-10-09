<?php
namespace Cigital\Safetynet;

class Session
{
    /**
     * Session constructor.
     *
     * @param string $session_id
     */
    public function __construct($session_id = null)
    {
        if (!is_null($session_id)) {
            session_id($session_id);
        }
    }

    /**
     * @param mixed $key
     * @param mixed $value
     *
     * @return $this
     */
    public function store($key, $value)
    {
        session_start();
        $_SESSION[$key] = $value;
        session_write_close();

        return $this;
    }

    /**
     * @param mixed $key
     *
     * @return mixed
     */
    public function get($key)
    {
        session_start();
        $value = $_SESSION[$key];
        session_write_close();

        return $value;
    }

    public function destroy()
    {
        session_start();
        session_unset();
        session_destroy();
        session_write_close();
        session_regenerate_id(true);
    }
}
