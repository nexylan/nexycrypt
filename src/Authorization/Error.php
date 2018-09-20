<?php

declare(strict_types=1);

namespace Nexy\NexyCrypt\Authorization;


final class Error
{
    /**
     * @var string
     */
    private $type;

    /**
     * @var string
     */
    private $detail;

    /**
     * @var int
     */
    private $status;

    /**
     * @param string $type
     * @param string $detail
     * @param int $status
     */
    public function __construct($type, $detail, $status)
    {
        $this->type = $type;
        $this->detail = $detail;
        $this->status = $status;
    }

    public function __toString()
    {
        return "[{$this->type}] {$this->detail}";
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
    public function getDetail()
    {
        return $this->detail;
    }

    /**
     * @return int
     */
    public function getStatus()
    {
        return $this->status;
    }
}
