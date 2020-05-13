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

namespace Nexy\NexyCrypt\Authorization\Challenge;

use Base64Url\Base64Url;
use Nexy\NexyCrypt\Authorization\Error;
use Nexy\NexyCrypt\PrivateKey;

/**
 * @internal
 *
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
final class ChallengeFactory
{
    /**
     * This class must be static.
     */
    private function __construct()
    {
    }

    /**
     * @param string[] $data
     */
    public static function create(string $type, array $data, PrivateKey $privateKey): ?ChallengeInterface
    {
        $status = $data['status'] ?? null;
        $url = $data['url'];
        $token = $data['token'];
        $header = [
            // need to be in precise order!
            'e' => Base64Url::encode($privateKey->getDetails()['rsa']['e']),
            'kty' => 'RSA',
            'n' => Base64Url::encode($privateKey->getDetails()['rsa']['n']),
        ];
        $authorizationKey = $token.'.'.Base64Url::encode(hash('sha256', json_encode($header), true));
        $error = isset($data['error'])
            ? new Error($data['error']['type'], $data['error']['detail'], $data['error']['status'])
            : null
        ;

        switch ($type) {
            case ChallengeInterface::HTTP_01:
                return new Http01Challenge($status, $url, $token, $authorizationKey, $error);
            case ChallengeInterface::DNS_01:
                return new Dns01Challenge($status, $url, $token, $authorizationKey, $error);
            case ChallengeInterface::TLS_SNI_01:
                return new TlsSni01Challenge($status, $url, $token, $authorizationKey, $error);
        }

        return null;
    }
}
