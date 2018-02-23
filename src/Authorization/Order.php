<?php

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
     * @var Authorization[]
     */
    private $authorizations = [];

    /**
     * @var string
     */
    private $finalizeUrl;

    /**
     * @param string $status
     * @param \DateTime $expires
     * @param Identifier[] $identifiers
     */
    public function __construct($status, \DateTime $expires, array $identifiers, $finalizeUrl)
    {
        Assert::allIsInstanceOf($identifiers, Identifier::class);

        $this->status = $status;
        $this->expires = $expires;
        $this->identifiers = $identifiers;
        $this->finalizeUrl = $finalizeUrl;
    }

    /**
     * @return string
     */
    public function getStatus()
    {
        return $this->status;
    }

    /**
     * @return \DateTime
     */
    public function getExpires()
    {
        return $this->expires;
    }

    /**
     * @return Identifier[]
     */
    public function getIdentifiers()
    {
        return $this->identifiers;
    }

    /**
     * @return Authorization[]
     */
    public function getAuthorizations()
    {
        return $this->authorizations;
    }

    public function addAuthorization(Authorization $authorization)
    {
        $this->authorizations[] = $authorization;
    }

    /**
     * @return string
     */
    public function getFinalizeUrl()
    {
        return $this->finalizeUrl;
    }
}
