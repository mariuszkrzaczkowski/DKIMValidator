<?php

declare(strict_types=1);

use PHPMailer\DKIMValidator\Message;

it(
    'rejects an empty message',
    function () {
        $message = new Message('');
    }
)->throws(InvalidArgumentException::class);

it(
    'rejects an incomplete message',
    function () {
        $message = new Message('test');
    }
)->throws(InvalidArgumentException::class);

it(
    'splits a message into headers and body',
    function () {
        $message = new Message("A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n");
        assertEquals("A: X\r\nB : Y\t\r\n\tZ  \r\n", $message->getRawHeaders());
        assertEquals(" C \r\nD \t E\r\n\r\n\r\n", $message->getBody());
    }
);

it(
    'parses headers correctly',
    function () {
        //Make a big messy header value to encode
        $utf8 = str_repeat('🐵👍éxçøԗႪ', 10);
        $qencoded = mb_encode_mimeheader($utf8, 'UTF-8', 'Q');
        $bencoded = mb_encode_mimeheader($utf8, 'UTF-8', 'B');
        $message = new Message(
            "A: X\r\nB : Y\t\r\n\tZ  \r\nQ1: $qencoded\r\nQ2: $bencoded\r\n\r\n C \r\nD \t E\r\n\r\n\r\n"
        );
        $headers = $message->getHeaders();
        assertEquals("A: X\r\n", $headers[0]->getRaw());
        assertEquals('A', $headers[0]->getLabel());
        assertEquals('a', $headers[0]->getLowerLabel());
        assertEquals('X', $headers[0]->getValue());
        assertEquals("B : Y\t\r\n\tZ  \r\n", $headers[1]->getRaw());
        assertEquals('B', $headers[1]->getLabel());
        assertEquals('b', $headers[1]->getLowerLabel());
        //Note that this gains a space before the Z due to unfolding
        assertEquals("Y\t Z  ", $headers[1]->getValue());
        assertEquals($qencoded, $headers[2]->getRawValue());
        assertEquals($utf8, $headers[2]->getValue());
        assertEquals($bencoded, $headers[3]->getRawValue());
        assertEquals($utf8, $headers[3]->getValue());
    }
);

it(
    'finds headers by name',
    function () {
        $message = new Message(
            "A: X\r\nB : Y\t\r\n\tZ  \r\nB:P\r\n\r\n C \r\nD \t E\r\n\r\n\r\n"
        );
        $headers = $message->getHeadersNamed('A');
        assertCount(1, $headers);
        assertEquals('X', $headers[0]->getValue());
        assertEquals('A', $headers[0]->getLabel());
        $headers = $message->getHeadersNamed('B');
        assertCount(2, $headers);
    }
);

it(
    'handles invalid headers correctly',
    function () {
        $message = new Message(
            "A: X\r\nB : Y\t\r\n\tZ  \r\nB:P\r\n\r\n C \r\nD \t E\r\n\r\n\r\n"
        );
        //For coverage
        $reflector = new ReflectionClass(Message::class);
        $method = $reflector->getMethod('parseHeaders');
        $method->setAccessible(true);
        $result = $method->invokeArgs($message, ['x']);
        assertIsArray($result);
        assertCount(0, $result);
    }
);
