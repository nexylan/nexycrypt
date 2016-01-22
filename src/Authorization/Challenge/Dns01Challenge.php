<?php

namespace Nexy\NexyCrypt\Authorization\Challenge;

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
}
