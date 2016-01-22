<?php

namespace Nexy\NexyCrypt;

use Base64Url\Base64Url;
use GuzzleHttp\Exception\ClientException;
use Nexy\NexyCrypt\Authorization\Authorization;
use Nexy\NexyCrypt\Authorization\Challenge\ChallengeFactory;
use Nexy\NexyCrypt\Authorization\Identifier;
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
     * @var PrivateKey
     */
    private $privateKey = null;

    /**
     * @var string
     */
    private $privateKeyPath;

    /**
     * @var string[][]
     */
    private $lastResponseHeaders = [];

    /**
     * Associative array of Let's Encrypt links.
     *
     * Updated on each request
     *
     * @var string[]
     */
    private $links = [];

    /**
     * @var string
     */
    private $regLocation;

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
     *
     * CAUTION: Be using this method, we assume that you agree with Let's Encrypt terms of service.
     * See https://letsencrypt.org/repository/ -> Let’s Encrypt Subscriber Agreement
     */
    public function register()
    {
        if (null === $this->privateKey) {
            $this->privateKey = new PrivateKey($this->privateKeyPath);
        }

        try {
            $this->signedPostRequest(null === $this->regLocation ? 'acme/new-reg' : $this->regLocation, [
                'resource' => null === $this->regLocation ? 'new-reg' : 'reg',
            ]);
        } catch (ClientException $e) {
            if (409 === $e->getResponse()->getStatusCode()) {
                // Registration location is now saved, try init again.
                $this->register();
            } else {
                throw $e;
            }
        }
    }

    public function agreeTerms()
    {
        $this->signedPostRequest($this->regLocation, [
            'resource' => 'reg',
            'agreement' => $this->links['terms-of-service'],
        ]);
    }

    /**
     * @param string $domain
     *
     * @return Authorization
     */
    public function authorize($domain)
    {
        $response = $this->signedPostRequest('acme/new-authz', [
            'resource' => 'new-authz',
            'identifier' => [
                'type' => 'dns',
                'value' => $domain,
            ],
        ]);

        $data = json_decode($response->getBody()->getContents(), true);

        $authorization = new Authorization();

        $authorization->setIdentifier(new Identifier($data['identifier']['type'], $data['identifier']['value']));
        $authorization->setStatus($data['status']);
        $authorization->setExpires(new \DateTime(substr($data['expires'], 0, -4)));
        foreach ($data['challenges'] as $challengeData) {
            $challenge = ChallengeFactory::create($challengeData['type'], $challengeData, $this->privateKey);
            $authorization->addChallenge($challenge);
        }

        return $authorization;
    }

    /**
     * @param string $uri
     * @param array  $payload
     *
     * @return ResponseInterface
     */
    private function signedPostRequest($uri, array $payload)
    {
        $header = [
            'alg' => 'RS256',
            'jwk' => [
                'kty' => 'RSA',
                'n' => Base64Url::encode($this->privateKey->getDetails()['rsa']['n']),
                'e' => Base64Url::encode($this->privateKey->getDetails()['rsa']['e']),
            ],
        ];

        $protected = $header;
        $protected['nonce'] = $this->getLastNonce();

        $payload64 = Base64Url::encode(json_encode($payload, JSON_UNESCAPED_SLASHES));
        $protected64 = Base64Url::encode(json_encode($protected));

        $signed64 = Base64Url::encode($this->privateKey->sign($protected64.'.'.$payload64));

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
        try {
            $response = $this->httpClient->request($method, $uri, $options);
        } catch (ClientException $e) {
            $response = $e->getResponse();

            throw $e;
        } finally {
            if (isset($response)) {
                $this->updateHeaders($response);
            }
        }

        return $response;
    }

    private function updateHeaders(ResponseInterface $response)
    {
        $this->lastResponseHeaders = $response->getHeaders();

        if (isset($this->lastResponseHeaders['Link'])) {
            foreach ($this->lastResponseHeaders['Link'] as $link) {
                preg_match('/^<(\S+)>;rel="(\S+)"$/', $link, $matches);
                $this->links[$matches[2]] = $matches[1];
            }
        }

        // Keep registration location for terms agreement.
        if (isset($this->lastResponseHeaders['Location'][0])) {
            $this->regLocation = $this->lastResponseHeaders['Location'][0];
        }

        //dump($response->getStatusCode(), $response->getBody()->getContents(), $this->lastResponseHeaders);
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
