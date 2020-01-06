<?php

namespace Nexy\NexyCrypt\Authorization\Challenge;

use Doctrine\Common\Collections\ArrayCollection;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
class ChallengeCollection extends ArrayCollection
{
    /**
     * @return Http01Challenge|null|false
     */
    public function getHttp01()
    {
        return $this->filter(function (ChallengeInterface $challenge) {
            return $challenge instanceof Http01Challenge;
        })->first();
    }

    /**
     * @return Dns01Challenge|null|false
     */
    public function getDns01()
    {
        return $this->filter(function (ChallengeInterface $challenge) {
            return $challenge instanceof Dns01Challenge;
        })->first();
    }

    /**
     * @return TlsSni01Challenge|null|false
     */
    public function getTlsSni01()
    {
        return $this->filter(function (ChallengeInterface $challenge) {
            return $challenge instanceof TlsSni01Challenge;
        })->first();
    }

    /**
     * @param string $type
     *
     * @return ChallengeInterface|null|false
     */
    public function getOfType($type)
    {
        return $this->filter(function (ChallengeInterface $challenge) use ($type) {
            return $type === $challenge->getType();
        })->first();
    }
}
