# NexyCrypt

Let's Encrypt ACME protocol PHP client.

Inspired by [analogic/lescript](https://github.com/analogic/lescript) project.

[![Latest Stable Version](https://poser.pugx.org/nexylan/nexycrypt/v/stable)](https://packagist.org/packages/nexylan/nexycrypt)
[![Latest Unstable Version](https://poser.pugx.org/nexylan/nexycrypt/v/unstable)](https://packagist.org/packages/nexylan/nexycrypt)
[![License](https://poser.pugx.org/nexylan/nexycrypt/license)](https://packagist.org/packages/nexylan/nexycrypt)

[![Total Downloads](https://poser.pugx.org/nexylan/nexycrypt/downloads)](https://packagist.org/packages/nexylan/nexycrypt)
[![Monthly Downloads](https://poser.pugx.org/nexylan/nexycrypt/d/monthly)](https://packagist.org/packages/nexylan/nexycrypt)
[![Daily Downloads](https://poser.pugx.org/nexylan/nexycrypt/d/daily)](https://packagist.org/packages/nexylan/nexycrypt)

## Installation

```bash
composer require nexylan/nexycrypt php-http/guzzle6-adapter
```

Why `php-http/guzzle6-adapter`? We are decoupled from any HTTP messaging client thanks to [HTTPlug](http://httplug.io/).

## Usage

See example root files.

## TODO

* Exception management
* Unit test
* Integration test with a fake API
* Symfony console (letsencrypt cli like)
* Save accepted agreement with a boolean getter (`agreement` on reg body)
* Implement dns-01 and tls-sni-01 challenges
* Use a JWT library to simplify code

## Usage

`$ composer install` 

`php example_dns01.php example.com 1` / `php example_http01.php example.com 1`

> Generation work with multiple domain / sub-domain in the same time. 

Copy generated file under public folder on `.well-known/acme-challenge` folder from you domain webroot.

`php example_dns01.php example.com 2` / `php example_http01.php example.com 2`

Get your certificate files on cert folder

> If the second step return an error, you must re-generate your challenge and token(s).

> Upload your certificate on your server, modify your web server config, that all.
