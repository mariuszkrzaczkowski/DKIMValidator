<?php

use PHPMailer\DKIMValidator\Validator;
use PHPMailer\DKIMValidator\Message;

it(
    'canonicalizes a message correctly',
    function () {
        //Examples from https://tools.ietf.org/html/rfc6376#section-3.4.5
        $rawMessage = "A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n";
        $relaxedHeader = "a:X\r\nb:Y Z\r\n";
        $relaxedBody = " C\r\nD E\r\n";
        $simpleHeader = "A: X\r\nB : Y\t\r\n\tZ  \r\n";
        $simpleBody = " C \r\nD \t E\r\n";
        $m = new Validator(new Message($rawMessage));
        $rh = $m->canonicalizeHeaders(
            $m->getMessage()->getHeaders(),
            Validator::CANONICALIZATION_HEADERS_RELAXED
        );
        $rb = $m->canonicalizeBody(
            Validator::CANONICALIZATION_BODY_RELAXED
        );
        $sh = $m->canonicalizeHeaders(
            $m->getMessage()->getHeaders(),
            Validator::CANONICALIZATION_HEADERS_SIMPLE
        );
        $sb = $m->canonicalizeBody(
            Validator::CANONICALIZATION_BODY_SIMPLE
        );
        assertEquals($relaxedHeader, $rh);
        assertEquals($relaxedBody, $rb);
        assertEquals($simpleHeader, $sh);
        assertEquals($simpleBody, $sb);
    }
);
