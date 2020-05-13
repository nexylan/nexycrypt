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

use Nexy\NexyCrypt\Authorization\Challenge\ChallengeCollection;
use Nexy\NexyCrypt\Authorization\Challenge\ChallengeInterface;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
final class Authorization
{
    /**
     * @var Identifier
     */
    private $identifier;

    /**
     * @var string
     */
    private $status;

    /**
     * @var \DateTime
     */
    private $expires;

    /**
     * @var bool
     */
    private $wildcard = false;

    /**
     * @var ChallengeInterface[]|ChallengeCollection
     */
    private $challenges;

    public function __construct(Identifier $identifier, string $status, \DateTime $expires, bool $wildcard)
    {
        $this->identifier = $identifier;
        $this->status = $status;
        $this->expires = $expires;
        $this->wildcard = $wildcard;
        $this->challenges = new ChallengeCollection();
    }

    public function getIdentifier(): Identifier
    {
        return $this->identifier;
    }

    public function getIdentifierDisplayName(): string
    {
        if ($this->isWildcard()) {
            return '*.'.$this->getIdentifier()->getValue();
        }

        return $this->getIdentifier()->getValue();
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
     * @return ChallengeInterface[]|ChallengeCollection
     */
    public function getChallenges(): ChallengeCollection
    {
        return $this->challenges;
    }

    public function addChallenge(ChallengeInterface $challenge): void
    {
        $this->challenges->add($challenge);
    }

    public function removeChallenge(ChallengeInterface $challenge): void
    {
        $this->challenges->removeElement($challenge);
    }

    public function isWildcard(): bool
    {
        return $this->wildcard;
    }
}
