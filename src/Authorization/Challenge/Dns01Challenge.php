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

use Base64Url\Base64Url;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
final class Dns01Challenge extends AbstractChallenge
{
    public function getType(): string
    {
        return ChallengeInterface::DNS_01;
    }

    public function getRecordName(): string
    {
        return '_acme-challenge';
    }

    public function getRecordType(): string
    {
        return 'TXT';
    }

    public function getRecordContent(): string
    {
        return Base64Url::encode(hash('sha256', $this->authorizationKey, true));
    }
}
