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

namespace Nexy\NexyCrypt\Exception;

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

    public function __construct(string $type, string $details, int $status, ?\Exception $previous = null)
    {
        $this->type = $type;
        $this->details = $details;

        parent::__construct(sprintf('[%s] %s', $this->type, $this->details), $status, $previous);
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getDetails(): string
    {
        return $this->details;
    }
}
