<?php

namespace Nexy\NexyCrypt\Authorization\Challenge;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
interface ChallengeInterface
{
    const HTTP_01 = 'http-01';
    const DNS_01 = 'dns-01';
    const TLS_SNI_01 = 'tls-sni-01';

    /**
     * @return string
     */
    public function getType();

    /**
     * @return string|null
     */
    public function getStatus();

    /**
     * @param string $status
     */
    public function setStatus($status);

    /**
     * @return string
     */
    public function getUri();

    /**
     * @param string $uri
     */
    public function setUri($uri);

    /**
     * @return string
     */
    public function getToken();

    /**
     * @param string $token
     */
    public function setToken($token);

    /**
     * @return string
     */
    public function getAuthorizationKey();

    /**
     * @param string $authorizationKey
     */
    public function setAuthorizationKey($authorizationKey);
}
