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

    public function __construct(string $type, string $detail, int $status)
    {
        $this->type = $type;
        $this->detail = $detail;
        $this->status = $status;
    }

    public function __toString()
    {
        return "[{$this->type}] {$this->detail}";
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getDetail(): string
    {
        return $this->detail;
    }

    public function getStatus(): int
    {
        return $this->status;
    }
}
