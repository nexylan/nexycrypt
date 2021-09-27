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

namespace Nexy\NexyCrypt;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
final class Certificate
{
    /**
     * Private generated key.
     *
     * privkey.pem
     *
     * @var string
     */
    private $privkey = '';

    /**
     * Public generated key.
     *
     * pubkey.pem
     *
     * @var string
     */
    private $pubkey = '';

    /**
     * Generated CSR.
     *
     * csr
     *
     * @var string
     */
    private $csr = '';

    /**
     * fullchain.pem.
     *
     * @var string
     */
    private $fullchain = '';

    /**
     * Provided certificate's cert.
     *
     * cert.pem
     *
     * @var string
     */
    private $cert = '';

    /**
     * Provided certificate's chain.
     *
     * chain.pem
     *
     * @var string
     */
    private $chain = '';

    /**
     * @var \DateTime|null
     */
    private $validFrom;

    /**
     * @var \DateTime|null
     */
    private $validTo;

    /**
     * Returns associative array with filename and content.
     *
     * @return string[]
     */
    public function getFilesArray(): array
    {
        return [
            'privkey.pem' => $this->privkey,
            'pubkey.pem' => $this->pubkey,
            'csr.pem' => $this->csr,
            'fullchain.pem' => $this->fullchain,
            'cert.pem' => $this->cert,
            'chain.pem' => $this->chain,
        ];
    }

    public function getPrivkey(): string
    {
        return $this->privkey;
    }

    public function setPrivkey(string $privkey): void
    {
        $this->privkey = $privkey;
    }

    public function getPubkey(): string
    {
        return $this->pubkey;
    }

    public function setPubkey(string $pubkey): void
    {
        $this->pubkey = $pubkey;
    }

    public function getCsr(): string
    {
        return $this->csr;
    }

    /**
     * Base64 decoded CSR content without Header tags.
     *
     * Useful for Let's Encrypt API.
     *
     * @see https://letsencrypt.github.io/acme-spec/#rfc.section.6.6
     */
    public function getRawCsr(): string
    {
        preg_match('~REQUEST-----(.*)-----END~s', $this->csr, $matches);

        return base64_decode($matches[1]);
    }

    public function setCsr(string $csr): void
    {
        $this->csr = $csr;
    }

    public function getFullchain(): string
    {
        return $this->fullchain;
    }

    public function setFullchain(string $fullchain): void
    {
        $this->fullchain = trim($fullchain);

        $fullchainSplit = preg_split(
            '/(-----BEGIN CERTIFICATE-----[\n\S]+-----END CERTIFICATE-----\n)\n/',
            $this->fullchain,
            -1,
            PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE
        );
        $this->setCert(array_shift($fullchainSplit));
        $this->setChain(implode("\n", $fullchainSplit));
    }

    public function getCert(): string
    {
        return $this->cert;
    }

    public function setCert(string $cert): void
    {
        $this->cert = $cert;

        $res = openssl_x509_parse($this->cert);
        $this->validFrom = new \DateTime();
        $this->validFrom->setTimestamp($res['validFrom_time_t']);
        $this->validTo = new \DateTime();
        $this->validTo->setTimestamp($res['validTo_time_t']);
    }

    public function getChain(): string
    {
        return $this->chain;
    }

    public function setChain(string $chain): void
    {
        $this->chain = $chain;
    }

    /**
     * @return \DateTime
     */
    public function getValidFrom(): ?\DateTime
    {
        return $this->validFrom;
    }

    /**
     * @return \DateTime
     */
    public function getValidTo(): ?\DateTime
    {
        return $this->validTo;
    }
}
