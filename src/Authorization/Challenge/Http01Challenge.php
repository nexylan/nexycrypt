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

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
final class Http01Challenge extends AbstractChallenge
{
    public function getType(): string
    {
        return ChallengeInterface::HTTP_01;
    }

    public function getDirectory(): string
    {
        return '.well-known/acme-challenge';
    }

    public function getFileName(): string
    {
        return $this->getToken();
    }

    public function getFileContent(): string
    {
        return $this->getAuthorizationKey();
    }

    public function getPath(): string
    {
        return sprintf('%s/%s', $this->getDirectory(), $this->getFileName());
    }
}
