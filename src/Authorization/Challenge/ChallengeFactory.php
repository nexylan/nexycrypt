<?php

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
     * @param string     $type
     * @param string[]   $data
     * @param PrivateKey $privateKey
     *
     * @return ChallengeInterface|null
     */
    public static function create($type, array $data, PrivateKey $privateKey)
    {
        switch ($type) {
            case ChallengeInterface::HTTP_01:
                $challenge = new Http01Challenge();
                break;
            case ChallengeInterface::DNS_01:
                $challenge = new Dns01Challenge();
                break;
            case ChallengeInterface::TLS_SNI_01:
                $challenge = new TlsSni01Challenge();
                break;
            default:
                return;
        }

        $challenge->setToken($data['token']);
        $challenge->setUrl($data['url']);
        $challenge->setStatus(isset($data['status']) ? $data['status'] : null);
        $challenge->setError(
            isset($data['error'])
                ? new Error($data['error']['type'], $data['error']['detail'], $data['error']['status'])
                : null
        );

        $header = [
            // need to be in precise order!
            'e' => Base64Url::encode($privateKey->getDetails()['rsa']['e']),
            'kty' => 'RSA',
            'n' => Base64Url::encode($privateKey->getDetails()['rsa']['n']),

        ];
        $authorizationKey = $challenge->getToken().'.'.Base64Url::encode(hash('sha256', json_encode($header), true));

        $challenge->setAuthorizationKey($authorizationKey);

        return $challenge;
    }
}
