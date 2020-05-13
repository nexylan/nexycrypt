<?php

declare(strict_types=1);

/*
 * This file is part of the Nexylan packages.
 *
 * (c) Nexylan SAS <contact@nexylan.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

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

    public function __construct(string $path)
    {
        $this->path = $path;

        if (is_file($this->path)) {
            $this->key = openssl_pkey_get_private('file://'.$this->path);
        } else {
            $this->key = openssl_pkey_new();
            @mkdir(\dirname($this->path), 0700, true);
            file_put_contents($this->path, $this->getOutput());
        }
        $this->details = openssl_pkey_get_details($this->key);
    }

    public function sign(string $data): string
    {
        openssl_sign($data, $signed, $this->key, 'SHA256');

        return $signed;
    }

    public function getOutput(): string
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

    public function getDetails(): array
    {
        return $this->details;
    }
}
