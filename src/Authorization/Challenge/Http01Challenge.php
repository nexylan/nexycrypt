<?php

namespace Nexy\NexyCrypt\Authorization\Challenge;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
final class Http01Challenge extends AbstractChallenge
{
    /**
     * @return string
     */
    public function getType()
    {
        return ChallengeInterface::HTTP_01;
    }

    /**
     * @return string
     */
    public function getDirectory()
    {
        return '.well-known/acme-challenge';
    }

    /**
     * @return string
     */
    public function getFileName()
    {
        return $this->getToken();
    }

    /**
     * @return string
     */
    public function getFileContent()
    {
        return $this->getAuthorizationKey();
    }

    /**
     * @return string
     */
    public function getPath()
    {
        return sprintf('%s/%s', $this->getDirectory(), $this->getFileName());
    }
}
