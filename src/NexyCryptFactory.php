<?php

namespace Nexy\NexyCrypt;

use Http\Client\HttpClient;
use Psr\Log\LoggerInterface;

final class NexyCryptFactory
{
    /**
     * @var string|null
     */
    private $defaultPrivateKeyPath;

    /**
     * @var string|null
     */
    private $endpoint;

    /**
     * @var HttpClient|null
     */
    private $httClient;

    /**
     * @var LoggerInterface|null
     */
    private $logger;

    /**
     * @var NexyCrypt[]
     */
    private $instances = [];

    /**
     * @param string|null $defaultPrivateKeyPath
     * @param string|null $endpoint
     * @param HttpClient|null $httClient
     */
    public function __construct($defaultPrivateKeyPath = null, $endpoint = null, HttpClient $httClient = null)
    {
        $this->defaultPrivateKeyPath = $defaultPrivateKeyPath;
        $this->endpoint = $endpoint;
        $this->httClient = $httClient;
    }

    /**
     * @param LoggerInterface $logger
     */
    public function setLogger($logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param string|null $privateKeyPath
     *
     * @return NexyCrypt
     */
    public function getInstance($privateKeyPath = null)
    {
        if (!array_key_exists($privateKeyPath, $this->instances)) {
            $this->instances[$privateKeyPath] = new NexyCrypt(
                null !== $privateKeyPath ? $privateKeyPath : $this->defaultPrivateKeyPath,
                $this->endpoint,
                $this->httClient
            );

            if (null !== $this->logger) {
                $this->instances[$privateKeyPath]->setLogger($this->logger);
            }
        }

        return $this->instances[$privateKeyPath];
    }
}