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

    public function __construct(?string $defaultPrivateKeyPath = null, ?string $endpoint = null, ?HttpClient $httClient = null)
    {
        $this->defaultPrivateKeyPath = $defaultPrivateKeyPath;
        $this->endpoint = $endpoint;
        $this->httClient = $httClient;
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function getInstance(?string $privateKeyPath = null): NexyCrypt
    {
        if (!\array_key_exists($privateKeyPath, $this->instances)) {
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
