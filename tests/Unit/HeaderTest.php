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
