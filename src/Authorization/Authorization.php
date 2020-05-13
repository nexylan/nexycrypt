<?php

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

    /**
     * @param bool $wildcard
     */
    public function __construct($wildcard)
    {
        $this->wildcard = $wildcard;
        $this->challenges = new ChallengeCollection();
    }

    /**
     * @return Identifier
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * @return string
     */
    public function getIdentifierDisplayName()
    {
        if ($this->isWildcard()) {
            return '*.'.$this->getIdentifier()->getValue();
        }

        return $this->getIdentifier()->getValue();
    }

    /**
     * @param Identifier $identifier
     */
    public function setIdentifier($identifier)
    {
        $this->identifier = $identifier;
    }

    /**
     * @return string
     */
    public function getStatus()
    {
        return $this->status;
    }

    /**
     * @param string $status
     */
    public function setStatus($status)
    {
        $this->status = $status;
    }

    /**
     * @return \DateTime
     */
    public function getExpires()
    {
        return $this->expires;
    }

    /**
     * @param \DateTime $expires
     */
    public function setExpires($expires)
    {
        $this->expires = $expires;
    }

    /**
     * @return ChallengeInterface[]|ChallengeCollection
     */
    public function getChallenges()
    {
        return $this->challenges;
    }

    /**
     * @param ChallengeInterface $challenge
     */
    public function addChallenge(ChallengeInterface $challenge)
    {
        $this->challenges->add($challenge);
    }

    /**
     * @param ChallengeInterface $challenge
     */
    public function removeChallenge(ChallengeInterface $challenge)
    {
        $this->challenges->removeElement($challenge);
    }

    /**
     * @return bool
     */
    public function isWildcard()
    {
        return $this->wildcard;
    }
}
