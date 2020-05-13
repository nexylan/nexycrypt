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

use Doctrine\Common\Collections\ArrayCollection;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
class ChallengeCollection extends ArrayCollection
{
    /**
     * @return Http01Challenge|false|null
     */
    public function getHttp01()
    {
        return $this->filter(function (ChallengeInterface $challenge) {
            return $challenge instanceof Http01Challenge;
        })->first();
    }

    /**
     * @return Dns01Challenge|false|null
     */
    public function getDns01()
    {
        return $this->filter(function (ChallengeInterface $challenge) {
            return $challenge instanceof Dns01Challenge;
        })->first();
    }

    /**
     * @return TlsSni01Challenge|false|null
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
     * @return ChallengeInterface|false|null
     */
    public function getOfType($type)
    {
        return $this->filter(function (ChallengeInterface $challenge) use ($type) {
            return $type === $challenge->getType();
        })->first();
    }
}
