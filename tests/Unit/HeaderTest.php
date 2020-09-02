<?php

declare(strict_types=1);

use PHPMailer\DKIMValidator\Header;
use PHPMailer\DKIMValidator\HeaderException;

it(
    'rejects a header starting with whitespace',
    function () {
        $message = new Header(" A: X\r\n");
    }
)->throws(HeaderException::class);

it(
    'rejects a header with trailing content',
    function () {
        $message = new Header("A: X\r\n123\r\n");
    }
)->throws(HeaderException::class);

it(
    'rejects an empty header',
    function () {
        $message = new Header('');
    }
)->throws(InvalidArgumentException::class);

/**
 * This was a real bug that appeared in OpenDKIM
 * @see https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=840015
 */
it(
    'correctly canonicalizes headers with early folds',
    function () {
        $header = new Header(
            "Subject:\r\n    long subject text continued on subsequent lines ...\r\n"
        );
        expect($header->getRelaxedCanonicalizedHeader())->toEqual(
            "subject:long subject text continued on subsequent lines ...\r\n"
        );
    }
);
