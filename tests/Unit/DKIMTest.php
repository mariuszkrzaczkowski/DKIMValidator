<?php

use PHPMailer\DKIMValidator\DKIM;

it(
    'splits a message into headers and body',
    function () {
        $dv = new DKIM("A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n");
        assertNotEmpty($dv->getHeaders());
        assertNotEmpty($dv->getBody());
    }
);

it(
    'canonicalizes a message correctly',
    function () {
        //Examples from https://tools.ietf.org/html/rfc6376#section-3.4.5
        $rawMessage = "A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n";
        $relaxedHeader = "a:X\r\nb:Y Z\r\n";
        $relaxedBody = " C\r\nD E\r\n";
        $simpleHeader = "A: X\r\nB : Y\t\r\n\tZ  \r\n";
        $simpleBody = " C \r\nD \t E\r\n";
        $m = new DKIM($rawMessage);
        $rh = $m->canonicalizeHeaders(
            $m->getHeaders(),
            DKIM::CANONICALIZATION_HEADERS_RELAXED
        );
        $rb = $m->canonicalizeBody(
            $m->getBody(),
            DKIM::CANONICALIZATION_BODY_RELAXED
        );
        $sh = $m->canonicalizeHeaders(
            $m->getHeaders(),
            DKIM::CANONICALIZATION_HEADERS_SIMPLE
        );
        $sb = $m->canonicalizeBody(
            $m->getBody(),
            DKIM::CANONICALIZATION_BODY_SIMPLE
        );
        assertEquals($relaxedHeader, $rh);
        assertEquals($relaxedBody, $rb);
        assertEquals($simpleHeader, $sh);
        assertEquals($simpleBody, $sb);
    }
);
