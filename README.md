# PHP DKIM Validator

A straightforward validation class for checking DKIM signatures and header settings. Requires PHP 7.3 or later.

Looking to *send* DKIM-signed email? Check out [PHPMailer](https://github.com/PHPMailer/PHPMailer)!

## Installation

```
composer require phpmailer/dkimvalidator
```

## Usage

```php
use PHPMailer\DKIMValidator\DKIM;
use PHPMailer\DKIMValidator\DKIMException;
require 'vendor/autoload.php';
//Put a whole raw email message in here
//Load the message directly from disk -
//don't copy & paste it as that will likely affect line breaks & charsets
$message  = file_get_contents('message.eml');
$dkimValidator = new DKIM($message);
try {
    if ($dkimValidator->validateBoolean()) {
        echo "Cool, it's valid";
    } else {
        echo 'Uh oh, dodgy email!';
    }
} catch (DKIMException $e) {
    echo $e->getMessage();
}
```

Good article on [problems facing DKIM](https://noxxi.de/research/breaking-dkim-on-purpose-and-by-chance.html).

# Changelog

* Original package [angrychimp/php-dkim](https://github.com/angrychimp/php-dkim);
* Forked by [teon/dkimvalidator](https://github.com/teonsystems/php-dkim).
* Forked into [phpmailer/dkimvalidator](https://github.com/PHPMailer/DKIMValidator) by Marcus Bointon (Synchro) in October 2019:
  * Major restructure
  * Test suite using pest
  * Cleanup for PSR-12 and PHP 7.3.
  * Strict standards & types enforced with phpcs, phpstan, psalm.
  * CI via GitHub actions.
  * More comprehensive analysis of DKIM elements.
  * Lots of bug fixes.
