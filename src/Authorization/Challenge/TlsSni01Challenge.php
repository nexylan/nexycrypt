<?php

namespace Nexy\NexyCrypt\Authorization\Challenge;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
final class TlsSni01Challenge extends AbstractChallenge
{
    /**
     * @return string
     */
    public function getType()
    {
        return ChallengeInterface::TLS_SNI_01;
    }
}
