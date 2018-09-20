<?php

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
    public function getUrl()
    {
        return $this->url;
    }

    /**
     * @param string $url
     */
    public function setUrl($url)
    {
        $this->url = $url;
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

    /**
     * @return Error|null
     */
    public function getError()
    {
        return $this->error;
    }

    /**
     * @param Error|null $error
     */
    public function setError($error)
    {
        $this->error = $error;
    }
}
