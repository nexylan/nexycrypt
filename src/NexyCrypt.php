<?php

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
use Nexy\NexyCrypt\Exception\AcmeApiException;
use Nexy\NexyCrypt\Exception\AcmeException;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;

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
     * @var LoggerInterface|null
     */
    private $logger = null;

    /**
     * @param string $privateKeyPath
     * @param string $endpoint
     * @param HttpClient|null $httpClient
     */
    public function __construct($privateKeyPath = null, $endpoint = null, HttpClient $httpClient = null)
    {
        $this->privateKeyPath = null === $privateKeyPath
            ? sys_get_temp_dir().'/nexycrypt.private_key'
            : $privateKeyPath;

        if (null !== $endpoint) {
            $this->endpoint = $endpoint;
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
    }

    /**
     * {@inheritdoc}
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * Generates or read privates key and starts registration.
     */
    public function register()
    {
        try {
            $this->signedPostRequest(null === $this->regLocation ? 'acme/new-reg' : $this->regLocation, [
                'resource' => null === $this->regLocation ? 'new-reg' : 'reg',
            ]);
        } catch (AcmeApiException $e) {
            if (409 === $e->getCode()) {
                $this->regLocation = $this->lastResponseHeaders['Location'][0];
                // Registration location is now saved, try init again.
                $this->register();
            } else {
                throw $e;
            }
        }
    }

    /**
     * See https://letsencrypt.org/repository/ -> Let’s Encrypt Subscriber Agreement.
     */
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

        return $this->getAuthorization(json_decode((string) $response->getBody(), true));
    }

    /**
     * @param ChallengeInterface $challenge
     *
     * @return bool
     */
    public function verifyChallenge(ChallengeInterface $challenge)
    {
        $this->signedPostRequest($challenge->getUri(), [
            'resource' => 'challenge',
            'type' => $challenge->getType(),
            'keyAuthorization' => $challenge->getAuthorizationKey(),
            'token' => $challenge->getToken(),
        ]);

        $authorization = null;
        do {
            usleep(100);
            $response = $this->request('GET', $this->links['up']);
            $authorization = $this->getAuthorization(json_decode((string) $response->getBody(), true), false);

            if ('invalid' === $authorization->getStatus()) {
                return false;
            }
        } while ('valid' !== $authorization->getStatus());

        return true;
    }

    /**
     * Generates private, public key and CSR for provided domains.
     *
     * @param string[] $domains
     *
     * @return Certificate
     */
    public function generateCertificate(array $domains)
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

    /**
     * Asks new-cert on Let's Encrypt to get and generate signed certificates.
     *
     * FullChain, cert and chain keys will be provider.
     * NexyCrypt::generateCertificate method MUST be called before this one.
     *
     * @param Certificate $certificate
     *
     * @return Certificate
     */
    public function signCertificate(Certificate $certificate)
    {
        $this->signedPostRequest('acme/new-cert', [
            'resource' => 'new-cert',
            'csr' => Base64Url::encode($certificate->getRawCsr()),
        ]);

        $certLocation = $this->lastResponseHeaders['Location'][0];

        do {
            $response = $this->request('GET', $certLocation);
        } while (200 !== $response->getStatusCode());

        $certificates = [];
        $certificates[] = $this->parsePemFromBody((string) $response->getBody());

        // Get chain
        $response = $this->request('GET', $this->links['up']);
        $certificates[] = $this->parsePemFromBody((string) $response->getBody());

        $certificate->setFullchain(implode("\n", $certificates));
        $certificate->setCert(array_shift($certificates));
        $certificate->setChain(implode("\n", $certificates));

        return $certificate;
    }

    /**
     * @return PrivateKey
     */
    public function getPrivateKey()
    {
        if (null === $this->privateKey) {
            $this->privateKey = new PrivateKey($this->privateKeyPath);
        }

        return $this->privateKey;
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
                'n' => Base64Url::encode($this->getPrivateKey()->getDetails()['rsa']['n']),
                'e' => Base64Url::encode($this->getPrivateKey()->getDetails()['rsa']['e']),
            ],
        ];

        $protected = $header;
        $protected['nonce'] = $this->getLastNonce();

        $payload64 = Base64Url::encode(json_encode($payload, JSON_UNESCAPED_SLASHES));
        $protected64 = Base64Url::encode(json_encode($protected));

        $signed64 = Base64Url::encode($this->getPrivateKey()->sign($protected64.'.'.$payload64));

        return $this->request('POST', $uri, [
            'header' => $header,
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $signed64,
        ]);
    }

    /**
     * We need to encapsulate httpClient request method to save some needed data.
     *
     * @param string $method
     * @param string $uri
     * @param array  $jsonData
     *
     * @return ResponseInterface
     */
    private function request($method, $uri, array $jsonData = null)
    {
        try {
            $response = $this->httpClient->send($method, $uri, [], $jsonData ? \json_encode($jsonData) : null);

            if ($this->logger) {
                $this->logger->info("[{$method}] {$uri}", (array) json_decode((string) $response->getBody(), true));
            }

            return $response;
        } catch (HttpException $e) {
            $response = $e->getResponse();
            $exceptionData = (array) json_decode((string) $response->getBody(), true);

            if (empty($exceptionData)) {
                throw new AcmeException($response->getBody()->getContents(), $e->getCode(), $e);
            }

            if ($this->logger) {
                $this->logger->error("[{$method}] {$uri}", $exceptionData);
            }

            throw new AcmeApiException($exceptionData['type'], $exceptionData['detail'], $exceptionData['status']);
        } catch (Exception $e) {
            throw new AcmeException($e->getMessage(), $e->getCode(), $e);
        } finally {
            if (isset($response)) {
                $this->updateHeaders($response);
            }
        }
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

    /**
     * @param array $data
     * @param bool  $withChallenges
     *
     * @return Authorization
     */
    private function getAuthorization(array $data, $withChallenges = true)
    {
        $authorization = new Authorization();

        $authorization->setIdentifier(new Identifier($data['identifier']['type'], $data['identifier']['value']));
        $authorization->setStatus($data['status']);
        $authorization->setExpires(new \DateTime(substr($data['expires'], 0, -4)));

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
     * @param string $body The API response body
     *
     * @return string
     */
    private function parsePemFromBody($body)
    {
        $pem = chunk_split(base64_encode($body), 64, "\n");

        return "-----BEGIN CERTIFICATE-----\n".$pem."-----END CERTIFICATE-----\n";
    }
}
