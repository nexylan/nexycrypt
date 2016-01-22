<?php

namespace Nexy\NexyCrypt\Authorization\Challenge;

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
    protected $uri;

    /**
     * @var string
     */
    protected $token;

    /**
     * @var string
     */
    protected $authorizationKey;

    /**
     * @return string
     */
    public function getStatus()
    {
        return $this->status;
    }

    /**
     * @param string $status
     */
    public function setStatus($status)
    {
        $this->status = $status;
    }

    /**
     * @return string
     */
    public function getUri()
    {
        return $this->uri;
    }

    /**
     * @param string $uri
     */
    public function setUri($uri)
    {
        $this->uri = $uri;
    }

    /**
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * @param string $token
     */
    public function setToken($token)
    {
        $this->token = $token;
    }

    /**
     * @return string
     */
    public function getAuthorizationKey()
    {
        return $this->authorizationKey;
    }

    /**
     * @param string $authorizationKey
     */
    public function setAuthorizationKey($authorizationKey)
    {
        $this->authorizationKey = $authorizationKey;
    }
}
