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
composer require nexylan/nexycrypt
```

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
