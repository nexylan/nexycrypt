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

use Base64Url\Base64Url;
use Http\Client\Common\HttpMethodsClient;
use Http\Client\Common\Plugin\BaseUriPlugin;
use Http\Client\Common\Plugin\ErrorPlugin;
use Http\Client\Common\Plugin\HeaderDefaultsPlugin;
use Http\Client\Common\PluginClient;
use Http\Client\Exception;
use Http\Client\Exception\HttpException;
use Http\Client\HttpClient;
use Http\Discovery\HttpClientDiscovery;
use Http\Discovery\MessageFactoryDiscovery;
use Http\Discovery\UriFactoryDiscovery;
use Nexy\NexyCrypt\Authorization\Authorization;
use Nexy\NexyCrypt\Authorization\Challenge\ChallengeFactory;
use Nexy\NexyCrypt\Authorization\Challenge\ChallengeInterface;
use Nexy\NexyCrypt\Authorization\Identifier;
use Nexy\NexyCrypt\Authorization\Order;
use Nexy\NexyCrypt\Exception\AcmeApiException;
use Nexy\NexyCrypt\Exception\AcmeException;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
class NexyCrypt implements LoggerAwareInterface
{
    /**
     * @var HttpMethodsClient
     */
    private $httpClient;

    /**
     * @var string
     */
    private $endpoint = 'https://acme-v02.api.letsencrypt.org';

    /**
     * @var PrivateKey|null
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
    private $kid;

    /**
     * @var LoggerInterface
     */
    private $logger;

    public function __construct(?string $privateKeyPath = null, ?string $endpoint = null, ?HttpClient $httpClient = null)
    {
        $this->privateKeyPath = null === $privateKeyPath
            ? sys_get_temp_dir().'/nexycrypt.private_key'
            : $privateKeyPath;

        if (null !== $endpoint) {
            $this->endpoint = rtrim($endpoint, '/');
        }

        $this->httpClient = new HttpMethodsClient(
            new PluginClient(
                $httpClient ?: HttpClientDiscovery::find(),
                [
                    new BaseUriPlugin(
                        UriFactoryDiscovery::find()->createUri($this->endpoint)
                    ),
                    new HeaderDefaultsPlugin([
                        'Accept' => 'application/json',
                        'Content-Type' => 'application/json',
                    ]),
                    new ErrorPlugin(),
                ]
            ),
            MessageFactoryDiscovery::find()
        );

        $this->logger = new NullLogger();
    }

    /**
     * {@inheritdoc}
     */
    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    /**
     * Generates or read privates key and starts registration.
     */
    public function register(): void
    {
        $response = $this->signedPostRequest('acme/new-acct', [
            'termsOfServiceAgreed' => true,
        ], true);
        $this->kid = $response->getHeader('Location')[0];
    }

    /**
     * @param string[] $domains
     */
    public function order(array $domains): Order
    {
        $response = $this->signedPostRequest('acme/new-order', [
            'identifiers' => array_map(function ($domain) {
                return [
                    'type' => 'dns',
                    'value' => $domain,
                ];
            }, $domains),
        ]);

        return $this->getOrder(json_decode((string) $response->getBody(), true));
    }

    public function verifyChallenge(Order $order, ChallengeInterface $challenge): void
    {
        $this->signedPostRequest($challenge->getUrl(), [
            'resource' => 'challenge',
            'type' => $challenge->getType(),
            'keyAuthorization' => $challenge->getAuthorizationKey(),
            'token' => $challenge->getToken(),
        ]);

        $authorization = null;
        do {
            // The authorization was already fetched once. Wait a bit before retrying.
            // @see https://tools.ietf.org/html/rfc8555#section-7.5.1
            if (null !== $authorization) {
                sleep(1);
            }
            $authorizationUrl = $this->links['up'];
            $response = $this->signedPostRequest($authorizationUrl);
            $authorization = $this->getAuthorization(json_decode((string) $response->getBody(), true), true);
            $order->addAuthorization($authorizationUrl, $authorization);

            if ('invalid' !== $authorization->getStatus()) {
                continue;
            }

            $authChallenge = $authorization->getChallenges()->getOfType($challenge->getType());
            if ($authChallenge->getError()) {
                throw new AcmeException((string) $authChallenge->getError(), $authChallenge->getError()->getStatus());
            }

            throw new AcmeException('Invalid challenge.');
        } while ('valid' !== $authorization->getStatus());
    }

    /**
     * Call the finalize URL of the order, then download and fill the certificate.
     */
    public function finalize(Order $order, Certificate $certificate): void
    {
        $finalizeData = json_decode((string) $this->signedPostRequest($order->getFinalizeUrl(), [
            'csr' => Base64Url::encode($certificate->getRawCsr()),
        ])->getBody(), true);

        $certificate->setFullchain(
            (string) $this->signedPostRequest($finalizeData['certificate'])->getBody()
        );
    }

    /**
     * Generates private, public key and CSR for provided domains.
     *
     * @param string[] $domains
     */
    public function generateCertificate(array $domains): Certificate
    {
        $certificate = new Certificate();
        $privateKey = openssl_pkey_new();
        $privateKeyDetails = openssl_pkey_get_details($privateKey);
        openssl_pkey_export($privateKey, $privateKeyOutput);

        $certificate->setPubkey($privateKeyDetails['key']);
        $certificate->setPrivkey($privateKeyOutput);

        $san = implode(',', array_map(function ($dns) {
            return 'DNS:'.$dns;
        }, $domains));
        $csrConf = tmpfile();
        $csrConfPath = stream_get_meta_data($csrConf)['uri'];

        // @see http://stackoverflow.com/a/9710863/1731473
        fwrite($csrConf,
'[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[req_distinguished_name]
[v3_req]
subjectAltName = '.$san.'
[v3_ca]
');

        $csr = openssl_csr_new([
            'CN' => $domains[0],
            // TODO: Make country configurable
            'ST' => 'France',
            'C' => 'FR',
            'O' => 'Unknown',
        ], $privateKey, [
            'config' => $csrConfPath,
            'digest_alg' => 'sha256',
        ]);
        openssl_csr_export($csr, $csrOut);
        $certificate->setCsr($csrOut);
        fclose($csrConf);

        return $certificate;
    }

    public function getPrivateKey(): PrivateKey
    {
        if (null === $this->privateKey) {
            $this->privateKey = new PrivateKey($this->privateKeyPath);
        }

        return $this->privateKey;
    }

    private function signedPostRequest(string $uri, array $payload = null, bool $useKeyHeader = false): ResponseInterface
    {
        $header = [
            'alg' => 'RS256',
            'nonce' => $this->getLastNonce(),
            'url' => "{$this->endpoint}{$this->normalizeUri($uri)}",
        ];

        if ($useKeyHeader) {
            $header['jwk'] = [
                'kty' => 'RSA',
                'n' => Base64Url::encode($this->getPrivateKey()->getDetails()['rsa']['n']),
                'e' => Base64Url::encode($this->getPrivateKey()->getDetails()['rsa']['e']),
            ];
        } else {
            $header['kid'] = $this->kid;
        }

        $payload64 = null !== $payload ? Base64Url::encode(json_encode($payload, JSON_UNESCAPED_SLASHES)) : '';
        $protected64 = Base64Url::encode(json_encode($header));

        $signed64 = Base64Url::encode($this->getPrivateKey()->sign($protected64.'.'.$payload64));

        return $this->request('POST', $uri, [
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $signed64,
        ], [
            'Content-Type' => 'application/jose+json',
        ]);
    }

    /**
     * We need to encapsulate httpClient request method to save some needed data.
     *
     * @param string[] $headers
     */
    private function request(string $method, string $uri, array $jsonData = null, array $headers = []): ResponseInterface
    {
        $uri = $this->normalizeUri($uri);
        $loggerKey = "[{$method}] {$uri}";
        try {
            $response = $this->httpClient->send(
                $method,
                $uri,
                $headers,
                $jsonData ? json_encode($jsonData) : null
            );

            $this->logger->info($loggerKey, (array) json_decode((string) $response->getBody(), true));

            return $response;
        } catch (HttpException $e) {
            $response = $e->getResponse();
            $responseBody = (string) $response->getBody();
            $exceptionData = (array) json_decode($responseBody, true);

            if (empty($exceptionData)) {
                $this->logger->error($loggerKey, [
                    'error' => $responseBody,
                    'status' => $response->getStatusCode(),
                ]);

                throw new AcmeException($responseBody, $e->getCode(), $e);
            }

            $this->logger->error($loggerKey, $exceptionData);

            throw new AcmeApiException($exceptionData['type'], $exceptionData['detail'], $exceptionData['status'] ?? 0);
        } catch (Exception $e) {
            $this->logger->error($loggerKey, ['error' => $e->getMessage()]);

            throw new AcmeException($e->getMessage(), $e->getCode(), $e);
        } finally {
            if (isset($response)) {
                $this->updateHeaders($response);
            }
        }
    }

    private function updateHeaders(ResponseInterface $response): void
    {
        $this->lastResponseHeaders = $response->getHeaders();

        if (isset($this->lastResponseHeaders['Link'])) {
            foreach ($this->lastResponseHeaders['Link'] as $link) {
                preg_match('/^<(\S+)>;rel="(\S+)"$/', $link, $matches);
                $this->links[$matches[2]] = $matches[1];
            }
        }
    }

    private function getLastNonce(): string
    {
        if (!isset($this->lastResponseHeaders['Replay-Nonce'][0])) {
            $this->request('HEAD', 'acme/new-nonce');
        }

        return $this->lastResponseHeaders['Replay-Nonce'][0];
    }

    private function getOrder(array $data, bool $withAuthorizations = true): Order
    {
        $order = new Order(
            $data['status'],
            new \DateTime(
                substr($data['expires'], 0, -4),
                new \DateTimeZone('UTC')
            ),
            array_map(function ($identifierData) {
                return new Identifier($identifierData['type'], $identifierData['value']);
            }, $data['identifiers']),
            $data['finalize']
        );

        if ($withAuthorizations) {
            foreach ($data['authorizations'] as $authorizationUrl) {
                $order->addAuthorization(
                    $authorizationUrl,
                    $this->getAuthorization(
                        json_decode(
                            (string) $this->signedPostRequest($authorizationUrl)->getBody(),
                            true
                        )
                    )
                );
            }
        }

        return $order;
    }

    private function getAuthorization(array $data, bool $withChallenges = true): Authorization
    {
        $authorization = new Authorization(
            new Identifier($data['identifier']['type'], $data['identifier']['value']),
            $data['status'],
            new \DateTime(substr($data['expires'], 0, -4)),
            \array_key_exists('wildcard', $data) ? $data['wildcard'] : false
        );

        if (true === $withChallenges) {
            foreach ($data['challenges'] as $challengeData) {
                $challenge = ChallengeFactory::create($challengeData['type'], $challengeData, $this->getPrivateKey());
                if (null !== $challenge) {
                    $authorization->addChallenge($challenge);
                }
            }
        }

        return $authorization;
    }

    /**
     * Remove the endpoint if present and normalize slashes.
     */
    private function normalizeUri(string $uri): string
    {
        return '/'.ltrim(str_replace($this->endpoint, '', $uri), '/');
    }
}
