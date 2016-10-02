<?php

namespace Nexy\NexyCrypt\Tests;

use PHPUnit\Framework\TestCase;
use Nexy\NexyCrypt\NexyCrypt;

class ExceptionTest extends TestCase
{
    /** @test */
    public function acmeApiExceptionTest()
    {
        //.well-known is not existed in your specified web document root file path.

        $client = new NexyCrypt(null, 'https://acme-staging.api.letsencrypt.org/');

        $this->expectException(\Nexy\NexyCrypt\Exception\AcmeApiException::class);

        $this->deleteRemoteFile('challenge');

        // the challenge file is not existed.
        try {
            $client->register();
            $client->agreeTerms();
            $challenge = unserialize(file_get_contents('tests/public/'.'acme-challenge'.'/challenge'));
            $client->verifyChallenge($challenge);
        } catch (AcmeApiException $e) {
            throw $e;
        }
    }

    public function deleteRemoteFile($fileName)
    {
        //this web hosting is only for testing, DO NOT use for ypur production!
        // it will be close in the irregular time.
        $ftpServer = 'nexycrypt.esy.es';
        $user = 'u431315912';
        $password = '8dpv8LvjEE';

        $connect = ftp_connect($ftpServer);
        $result = ftp_login($connect, $user, $password);

        if($result === false) {
            die('ftp logn is failed.');
        }

        ftp_chdir($connect, '.well-known');
        ftp_chdir($connect, 'acme-challenge');

        ftp_delete($connect, $fileName);

        ftp_close($connect);
    }
}
