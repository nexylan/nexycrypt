<?php

namespace Nexy\NexyCrypt;

use Base64Url\Base64Url;
use GuzzleHttp\Exception\ClientException;
use Psr\Http\Message\ResponseInterface;

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
    private $endpoint = 'https://acme-v01.api.letsencrypt.org/';

    /**
     * @var string
     */
    private $privateKeyPath;

    /**
     * @var resource
     */
    private $privateKey;

    /**
     * @var array
     */
    private $privateKeyDetails;

    /**
     * @var string[][]
     */
    private $lastResponseHeaders = [];

    /**
     * @param string $privateKeyPath
     * @param string $endpoint
     */
    public function __construct($privateKeyPath = null, $endpoint = null)
    {
        $this->privateKeyPath = null === $privateKeyPath
            ? sys_get_temp_dir().'/nexycrypt.private_key'
            : $privateKeyPath;

        if (null !== $endpoint) {
            $this->endpoint = $endpoint;
        }

        $this->httpClient = new \GuzzleHttp\Client([
            'base_uri' => $this->endpoint,
            'headers' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
            ],
        ]);
    }

    /**
     * Generates or read privates key and starts registration.
     */
    public function init()
    {
        if (is_file($this->privateKeyPath)) {
            $this->privateKey = openssl_pkey_get_private('file://'.$this->privateKeyPath);
        } else {
            $this->privateKey = openssl_pkey_new();
            openssl_pkey_export($this->privateKey, $privateKeyOutput);
            file_put_contents($this->privateKeyPath, $privateKeyOutput);
        }
        $this->privateKeyDetails = openssl_pkey_get_details($this->privateKey);

        try {
            $this->signedPostRequest('acme/new-reg', [
                'resource' => 'new-reg',
            ]);
        } catch (ClientException $e) {
            if (409 !== $e->getResponse()->getStatusCode()) {
                throw $e;
            }
        }
    }

    /**
     * @param string $uri
     * @param array $payload
     *
     * @return ResponseInterface
     */
    private function signedPostRequest($uri, array $payload)
    {
        $header = [
            'alg' => 'RS256',
            'jwk' => [
                'kty' => 'RSA',
                'n' => Base64Url::encode($this->privateKeyDetails['rsa']['n']),
                'e' => Base64Url::encode($this->privateKeyDetails['rsa']['e']),
            ],
        ];

        $protected = $header;
        $protected['nonce'] = $this->getLastNonce();

        $payload64 = Base64Url::encode(json_encode($payload, JSON_UNESCAPED_SLASHES));
        $protected64 = Base64Url::encode(json_encode($protected));

        openssl_sign($protected64.'.'.$payload64, $signed, $this->privateKey, 'SHA256');
        $signed64 = Base64Url::encode($signed);

        return $this->request('POST', $uri, [
            'json' => [
                'header' => $header,
                'protected' => $protected64,
                'payload' => $payload64,
                'signature' => $signed64,
            ],
        ]);
    }

    /**
     * We need to encapsulate httpClient request method to save some needed data.
     *
     * @param string $method
     * @param string $uri
     * @param array  $options
     *
     * @return ResponseInterface
     */
    private function request($method, $uri, array $options = [])
    {
        $response = $this->httpClient->request($method, $uri, $options);

        $this->lastResponseHeaders = $response->getHeaders();

        return $response;
    }

    /**
     * @return string
     */
    private function getLastNonce()
    {
        if (!isset($this->lastResponseHeaders['Replay-Nonce'][0])) {
            $this->request('GET', 'directory');
        }

        return $this->lastResponseHeaders['Replay-Nonce'][0];
    }
}
