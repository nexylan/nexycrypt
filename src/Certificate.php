<?php

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
    private $privkey;

    /**
     * Public generated key.
     *
     * pubkey.pem
     *
     * @var string
     */
    private $pubkey;

    /**
     * Generated CSR.
     *
     * csr
     *
     * @var string
     */
    private $csr;

    /**
     * fullchain.pem.
     *
     * @var string
     */
    private $fullchain;

    /**
     * Provided certificate's cert.
     *
     * cert.pem
     *
     * @var string
     */
    private $cert;

    /**
     * Provided certificate's chain.
     *
     * chain.pem
     *
     * @var string
     */
    private $chain;

    /**
     * Returns associative array with filename and content.
     *
     * @return string[]
     */
    public function getFilesArray()
    {
        return [
            'privkey.pem' => $this->privkey,
            'pubkey.pem' => $this->pubkey,
            'csr' => $this->csr,
            'fullchain.pem' => $this->fullchain,
            'cert.pem' => $this->cert,
            'chain.pem' => $this->chain,
        ];
    }

    /**
     * @return string
     */
    public function getPrivkey()
    {
        return $this->privkey;
    }

    /**
     * @param string $privkey
     */
    public function setPrivkey($privkey)
    {
        $this->privkey = $privkey;
    }

    /**
     * @return string
     */
    public function getPubkey()
    {
        return $this->pubkey;
    }

    /**
     * @param string $pubkey
     */
    public function setPubkey($pubkey)
    {
        $this->pubkey = $pubkey;
    }

    /**
     * @return string
     */
    public function getCsr()
    {
        return $this->csr;
    }

    /**
     * Base64 decoded CSR content without Header tags.
     *
     * Useful for Let's Encrypt API.
     *
     * @see https://letsencrypt.github.io/acme-spec/#rfc.section.6.6
     *
     * @return string
     */
    public function getRawCsr()
    {
        preg_match('~REQUEST-----(.*)-----END~s', $this->csr, $matches);

        return base64_decode($matches[1]);
    }

    /**
     * @param string $csr
     */
    public function setCsr($csr)
    {
        $this->csr = $csr;
    }

    /**
     * @return string
     */
    public function getFullchain()
    {
        return $this->fullchain;
    }

    /**
     * @param string $fullchain
     */
    public function setFullchain($fullchain)
    {
        $this->fullchain = $fullchain;
    }

    /**
     * @return string
     */
    public function getCert()
    {
        return $this->cert;
    }

    /**
     * @param string $cert
     */
    public function setCert($cert)
    {
        $this->cert = $cert;
    }

    /**
     * @return string
     */
    public function getChain()
    {
        return $this->chain;
    }

    /**
     * @param string $chain
     */
    public function setChain($chain)
    {
        $this->chain = $chain;
    }
}
