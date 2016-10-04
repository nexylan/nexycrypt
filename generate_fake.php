<?php

// generate the fake .well-known folder and upload the folder to the testing web hosting.

use Nexy\NexyCrypt\Authorization\Challenge\Http01Challenge;
use Nexy\NexyCrypt\Exception\AcmeApiException;
use Nexy\NexyCrypt\NexyCrypt;

require_once __DIR__.'/vendor/autoload.php';

if ($argc > 2) {
    echo 'You have to pass too many arguments.'.PHP_EOL;
    exit(1);
}

if(isset($argv[1])) {
    $step = intval($argv[1]);
} else {
    echo 'You have to pass the step arguments.'.PHP_EOL;
    exit(1);
}

$accounts = json_decode(file_get_contents('tests/ftpserver.json'), true);
$domain = $accounts['ftpserver'];

// First commented line is for production.
//$client = new NexyCrypt();
$client = new NexyCrypt(null, 'https://acme-staging.api.letsencrypt.org/');

try {
    if (0 === $step) {
        // create the required account private key
        $client->create();
    }

    if (1 === $step) {
        $client->register();
        $client->agreeTerms();
    }

    if (2 === $step) {
        $client->register();
        $client->agreeTerms();

        @mkdir('tests/public');

        $authorization = $client->authorize($domain);

        $challenge = $authorization->getChallenges()->getHttp01();

        @mkdir('tests/public/acme-challenge');
        file_put_contents('tests/public/'.'acme-challenge'.'/'.$challenge->getFileName(), $challenge->getFileContent());
        file_put_contents('tests/public/'.'acme-challenge'.'/challenge', serialize($challenge));
    }

    if (3 === $step) {
        // upload file to the remote server
        $accounts = json_decode(file_get_contents('tests/ftpserver.json'), true);
        $user = $accounts['username'];

        // the ftp server password is temporarily created and DO NOT use this value to do other things.
        // the free web hosting will be closed or reset at the irregular time.
        $password = $accounts['password'];
        $ftpServer = $accounts['ftpserver'];

        // set up basic ftp connection
        $connectId = ftp_connect($ftpServer);

        // login with username and password
        $loginResult = ftp_login($connectId, $user, $password);

        ftp_pasv($connectId, true);

        if (!$loginResult) {
            // PHP will already have raised an E_WARNING level message in this case
            echo "can't login";
            exit(1);
        }

        @ftp_mkdir($connectId, '.well-known');
        @ftp_mkdir($connectId, '.well-known/acme-challenge');

        ftp_chdir($connectId, '.well-known/acme-challenge');

        // upload the files from the folders
        $filePath = 'tests/public/acme-challenge';
        $filesArr = scandir($filePath);
        $fileCount = count($filesArr);
        for($index=2;$index<$fileCount;$index++) {
            $result = ftp_put($connectId, $filesArr[$index], $filePath.'/'.$filesArr[$index], FTP_ASCII);
            if ($result === false) {
                echo 'cannot upload file: '.$filesArr[$index];
                exit(1);
            }
        }

        ftp_close($connectId);
    }

    exit(0);
} catch (AcmeApiException $e) {
    var_dump($e->getDetails());

    exit(1);
}
