<?php

namespace Nexy\NexyCrypt\Authorization\Challenge;

use Base64Url\Base64Url;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
final class Dns01Challenge extends AbstractChallenge
{
    /**
     * @return string
     */
    public function getType()
    {
        return ChallengeInterface::DNS_01;
    }

    /**
     * @return string
     */
    public function getRecordName()
    {
        return '_acme-challenge';
    }

    /**
     * @return string
     */
    public function getRecordType()
    {
        return 'TXT';
    }

    /**
     * @return string
     */
    public function getRecordContent()
    {
        return Base64Url::encode(hash('sha256', $this->authorizationKey, true));
    }
}
