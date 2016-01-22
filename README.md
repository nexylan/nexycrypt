# NexyCrypt

Let's Encrypt ACME protocol PHP client.

Inspired by [analogic/lescript](https://github.com/analogic/lescript) project.

## TODO

* Exception management
* Unit test
* Integration test with a fake API
* Symfony console (letsencrypt cli like)
* Save accepted agreement with a boolean getter (`agreement` on reg body)
* Implement dns-01 and tls-sni-01 challenges
* Use a JWT library to simplify code
