<?php

namespace Nexy\NexyCrypt\Exception;

use Exception;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
class AcmeApiException extends AcmeException
{
    /**
     * @var string
     */
    private $type;

    /**
     * @var string
     */
    private $details;

    /**
     * @param string         $type
     * @param int            $details
     * @param Exception      $status
     * @param Exception|null $previous
     */
    public function __construct($type, $details, $status, Exception $previous = null)
    {
        $this->type = $type;
        $this->details = $details;

        parent::__construct(sprintf('[%s] %s', $this->type, $this->details), $status, $previous);
    }

    /**
     * @return string
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * @return string
     */
    public function getDetails()
    {
        return $this->details;
    }
}
