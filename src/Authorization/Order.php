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

namespace Nexy\NexyCrypt\Authorization;

use Webmozart\Assert\Assert;

final class Order
{
    /**
     * @var string
     */
    private $status;

    /**
     * @var \DateTime
     */
    private $expires;

    /**
     * @var Identifier[]
     */
    private $identifiers = [];

    /**
     * Authorization list, the url is the key.
     *
     * @var array<string, Authorization>
     */
    private $authorizations = [];

    /**
     * @var string
     */
    private $finalizeUrl;

    /**
     * @param Identifier[] $identifiers
     */
    public function __construct(string $status, \DateTime $expires, array $identifiers, string $finalizeUrl)
    {
        Assert::allIsInstanceOf($identifiers, Identifier::class);

        $this->status = $status;
        $this->expires = $expires;
        $this->identifiers = $identifiers;
        $this->finalizeUrl = $finalizeUrl;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function getExpires(): \DateTime
    {
        return $this->expires;
    }

    /**
     * @return Identifier[]
     */
    public function getIdentifiers(): array
    {
        return $this->identifiers;
    }

    /**
     * @return Authorization[]
     */
    public function getAuthorizations(): array
    {
        return $this->authorizations;
    }

    public function addAuthorization(string $url, Authorization $authorization): void
    {
        $this->authorizations[$url] = $authorization;
    }

    public function getFinalizeUrl(): string
    {
        return $this->finalizeUrl;
    }
}
