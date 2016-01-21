<?php

namespace Nexy\NexyCrypt;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
class Client
{
    /**
     * @var \GuzzleHttp\Client
     */
    private $httpClient;

    /**
     * @var string
     */
    private $ca = 'https://acme-v01.api.letsencrypt.org';

    /**
     * @param string $ca
     */
    public function __construct($ca = null)
    {
        if (null !== $ca) {
            $this->ca = $ca;
        }

        $this->httpClient = new \GuzzleHttp\Client([
            'base_uri' => $this->ca.'/acme/'
        ]);
    }
}
