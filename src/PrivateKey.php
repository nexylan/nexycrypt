<?php

namespace Nexy\NexyCrypt;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
final class PrivateKey
{
    /**
     * @var string
     */
    private $path;

    /**
     * @var resource
     */
    private $key;

    /**
     * @var array
     */
    private $details;

    /**
     * @param string $path
     */
    public function __construct($path)
    {
        $this->path = $path;

        if (is_file($this->path)) {
            $this->key = openssl_pkey_get_private('file://'.$this->path);
        } else {
            $this->key = openssl_pkey_new();
            @mkdir(dirname($this->path), 0700, true);
            file_put_contents($this->path, $this->getOutput());
        }
        $this->details = openssl_pkey_get_details($this->key);
    }

    /**
     * @param string $data
     *
     * @return string
     */
    public function sign($data)
    {
        openssl_sign($data, $signed, $this->key, 'SHA256');

        return $signed;
    }

    /**
     * @return string
     */
    public function getOutput()
    {
        openssl_pkey_export($this->key, $privateKeyOutput);

        return $privateKeyOutput;
    }

    /**
     * @return resource
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return array
     */
    public function getDetails()
    {
        return $this->details;
    }
}
