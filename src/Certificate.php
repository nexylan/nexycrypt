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
     * private.pem
     *
     * @var string
     */
    private $private;

    /**
     * Public generated key.
     *
     * public.pem
     *
     * @var string
     */
    private $public;

    /**
     * Generated CSR.
     *
     * csr
     *
     * @var string
     */
    private $csr;

    /**
     *
     * fullchain.pem
     *
     * @var string
     */
    private $fullChain;

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
     * @return string
     */
    public function getPrivate()
    {
        return $this->private;
    }

    /**
     * @param string $private
     */
    public function setPrivate($private)
    {
        $this->private = $private;
    }

    /**
     * @return string
     */
    public function getPublic()
    {
        return $this->public;
    }

    /**
     * @param string $public
     */
    public function setPublic($public)
    {
        $this->public = $public;
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
    public function getFullChain()
    {
        return $this->fullChain;
    }

    /**
     * @param string $fullChain
     */
    public function setFullChain($fullChain)
    {
        $this->fullChain = $fullChain;
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
