<?php

use PHPMailer\DKIMValidator\Header;
use PHPMailer\DKIMValidator\Message;
use PHPMailer\DKIMValidator\Validator;
use PHPMailer\DKIMValidator\ValidatorException;

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

it(
    'extracts DKIM tags from a signature header correctly',
    function () {
        $header = new Header(
        //These line breaks *must* be CRLF, so make them explicit
            "DKIM-Signature: v=1; d=example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; c=relaxed/simple;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ=="
        );
        $tags = Validator::extractDKIMTags($header);
        assertEquals('rsa-sha256', $tags['a']);
        assertEquals(
            'ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp' .
            'T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbmeoF' .
            'MSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQkIWnRd0' .
            '43/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5oRh7Z0ZEl+' .
            'n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==',
            $tags['b']
        );
        assertEquals('g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=', $tags['bh']);
        assertEquals('relaxed/simple', $tags['c']);
        assertEquals('example.com', $tags['d']);
        assertEquals('Date:To:From:Subject:Message-ID:X-Mailer:Content-Type', $tags['h']);
        assertEquals('6', $tags['l']);
        assertEquals('dns/txt', $tags['q']);
        assertEquals('phpmailer', $tags['s']);
        assertEquals('1570645905', $tags['t']);
        assertEquals('1', $tags['v']);
    }
);

it(
    'rejects attempts to extract DKIM tags from a non-DKIM header',
    function () {
        $header = new Header("a:b\r\n");
        $tags = Validator::extractDKIMTags($header);
    }
)->throws(InvalidArgumentException::class);

it(
    'validates a message',
    function () {
        $validator = new Validator(new Message(file_get_contents(__DIR__ . '/../message.eml')));
        $validation = $validator->validate();
        assertArrayHasKey('valid', $validation);
        assertFalse($validation['valid']);
        $validation = $validator->validateBoolean();
        assertFalse($validation);
    }
);
it(
    'detects a missing required selector DKIM tag',
    function () {
        //This is missing an 's' DKIM tag
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; c=relaxed/simple;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message));
        $validation = $validator->validate();
        assertArrayHasKey('valid', $validation);
        assertFalse($validation['valid']);
        throw new ValidatorException();
    }
)->throws(ValidatorException::class);

it(
    'detects an invalid DKIM version tag',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=9; d=example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; c=relaxed/simple;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message));
        $validation = $validator->validate();
        assertArrayHasKey('valid', $validation);
        assertFalse($validation['valid']);
        throw new ValidatorException();
    }
)->throws(ValidatorException::class);

it(
    'detects an invalid DKIM header canonicalization algorithm tag',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; c=foo/simple;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message));
        $validation = $validator->validate();
        assertArrayHasKey('valid', $validation);
        assertFalse($validation['valid']);
        throw new ValidatorException();
    }
)->throws(ValidatorException::class);

it(
    'detects an invalid DKIM body canonicalization algorithm tag',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; c=relaxed/foo;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message));
        $validation = $validator->validate();
        assertArrayHasKey('valid', $validation);
        assertFalse($validation['valid']);
        throw new ValidatorException();
    }
)->throws(ValidatorException::class);

it(
    'detects a truncated DKIM body length tag',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=999; t=1570645905; c=relaxed/simple;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message));
        $validation = $validator->validate();
        assertArrayHasKey('valid', $validation);
        assertFalse($validation['valid']);
        throw new ValidatorException();
    }
)->throws(ValidatorException::class);

it(
    'detects a mismatched identifier and domain DKIM tags',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=user@example.net; s=phpmailer;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; c=relaxed/simple;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message));
        $validation = $validator->validate();
        assertArrayHasKey('valid', $validation);
        assertFalse($validation['valid']);
        throw new ValidatorException();
    }
)->throws(ValidatorException::class);
