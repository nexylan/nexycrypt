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

use Nexy\NexyCrypt\Authorization\Error;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
interface ChallengeInterface
{
    public const HTTP_01 = 'http-01';
    public const DNS_01 = 'dns-01';
    public const TLS_SNI_01 = 'tls-sni-01';

    public function getType(): string;

    public function getStatus(): string;

    public function getUrl(): string;

    public function getToken(): string;

    public function getAuthorizationKey(): string;

    public function getError(): ?Error;
}
