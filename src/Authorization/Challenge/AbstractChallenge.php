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

namespace Nexy\NexyCrypt\Authorization\Challenge;

use Nexy\NexyCrypt\Authorization\Error;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
abstract class AbstractChallenge implements ChallengeInterface
{
    /**
     * @var string
     */
    protected $status;

    /**
     * @var string
     */
    protected $url;

    /**
     * @var string
     */
    protected $token;

    /**
     * @var string
     */
    protected $authorizationKey;

    /**
     * @var Error|null
     */
    protected $error;

    final public function __construct(string $status, string $url, string $token, string $authorizationKey, ?Error $error)
    {
        $this->status = $status;
        $this->url = $url;
        $this->token = $token;
        $this->authorizationKey = $authorizationKey;
        $this->error = $error;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getAuthorizationKey(): string
    {
        return $this->authorizationKey;
    }

    public function getError(): ?Error
    {
        return $this->error;
    }
}
