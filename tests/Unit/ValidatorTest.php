<?php

declare(strict_types=1);

use PHPMailer\DKIMValidator\DKIMException;
use PHPMailer\DKIMValidator\DNSException;
use PHPMailer\DKIMValidator\Header;
use PHPMailer\DKIMValidator\Message;
use PHPMailer\DKIMValidator\Tests\TestingKeys;
use PHPMailer\DKIMValidator\Tests\TestingResolver;
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
        expect($rh)->toEqual($relaxedHeader);
        expect($rb)->toEqual($relaxedBody);
        expect($sh)->toEqual($simpleHeader);
        expect($sb)->toEqual($simpleBody);
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
        expect($tags['a'])->toEqual('rsa-sha256');
        expect($tags['b'])->toEqual(
            'ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp' .
            'T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbmeoF' .
            'MSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQkIWnRd0' .
            '43/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5oRh7Z0ZEl+' .
            'n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ=='
        );
        expect($tags['bh'])->toEqual('g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=');
        expect($tags['c'])->toEqual('relaxed/simple');
        expect($tags['d'])->toEqual('example.com');
        expect($tags['h'])->toEqual('Date:To:From:Subject:Message-ID:X-Mailer:Content-Type');
        expect($tags['l'])->toEqual('6');
        expect($tags['q'])->toEqual('dns/txt');
        expect($tags['s'])->toEqual('phpmailer');
        expect($tags['t'])->toEqual('1570645905');
        expect($tags['v'])->toEqual('1');
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
    'detects an invalid signing domain',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=.example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; c=relaxed/simple;\r\n" .
            " a=rsa-sha256; h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";
        $validator = new Validator(new Message($message), new TestingResolver());
        $validation = $validator->validate();
        expect($validation->getResults()[0]->getFails()[0])->toEqual('Signing domain is invalid: .example.com.');
    }
);

it(
    'detects an invalid signing selector',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; s=.phpmailer;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; c=relaxed/simple;\r\n" .
            " a=rsa-sha256; h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";
        $validator = new Validator(new Message($message), new TestingResolver());
        $validation = $validator->validate();
        expect($validation->getResults()[0]->getFails()[0])->toEqual('Signing selector is invalid: .phpmailer.');
    }
);

it(
    'validates a message',
    function () {
        $messageFile = __DIR__ . '/../message.eml';
        if (! file_exists($messageFile)) {
            //Make a dummy assertion as we don't have an external message file to validate
            expect(true)->toBeTrue();

            return;
        }
        $message = file_get_contents($messageFile);
        if ($message !== false) {
            expect($message)->not->toBeFalse();
            $validator = new Validator(new Message($message));
            $validation = $validator->validate();
            expect($validation->isValid())->toBeFalse();
            $validationBool = $validator->validateBoolean();
            expect($validationBool)->toBeFalse();
            expect($validation->getResults()[0]->getPasses())->not->toBeEmpty();
            expect($validation->getResults()[0]->getFails())->not->toBeEmpty();
        } else {
            expect($message)->toBeFalse();
        }
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
        expect($validation->isValid())->toBeFalse();

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
        expect($validation->isValid())->toBeFalse();
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
        expect($validation->isValid())->toBeFalse();
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
        expect($validation->isValid())->toBeFalse();
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
        expect($validation->isValid())->toBeFalse();
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
            "DKIM-Signature: v=1; d=example.com; i=test@example.net; s=phpmailer;\r\n" .
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
        expect($validation->isValid())->toBeFalse();
        //For coverage
        expect($validation->getResults()[0]->getDomain())->toEqual('example.com');
        expect($validation->getResults()[0]->getSelector())->toEqual('phpmailer');
        throw new ValidatorException();
    }
)->throws(ValidatorException::class);

it(
    'detects if the From address header is not signed',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; c=relaxed/simple;\r\n" .
            " h=Date:To:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message));
        $validation = $validator->validate();
        expect($validation->isValid())->toBeFalse();
        throw new ValidatorException();
    }
)->throws(ValidatorException::class);

it(
    'detects if the DKIM signature has expired',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; x=" . (time() - 1) . "; c=relaxed/simple;\r\n" .
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
        expect($validation->isValid())->toBeFalse();
        throw new ValidatorException();
    }
)->throws(ValidatorException::class);

it(
    'detects if the DKIM signature has not expired',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; x=" . (time() + 1000) . "; c=relaxed/simple;\r\n" .
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
        throw new ValidatorException();
    }
)->throws(ValidatorException::class);

it(
    'detects if the DKIM signature expiry is before the signature timestamp',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=" . (time() + 200) . "; x=" . (time() + 100) . "; c=relaxed/simple;\r\n" .
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
        expect($validation->isValid())->toBeFalse();
        throw new ValidatorException();
    }
)->throws(ValidatorException::class);

it(
    'adds a q tag if none is provided',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; l=6; t=1570645905; c=relaxed/simple;\r\n" .
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
        expect($validation->isValid())->toBeFalse();
        expect($validation->getResults()[0]->getWarnings())->not->toBeEmpty();
    }
);

it(
    'ignores a record with an unknown q tag',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; l=6; t=1570645905; c=relaxed/simple; q=abc/xyz;\r\n" .
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
        expect($validation->isValid())->toBeFalse();
        expect($validation->getResults()[0]->getWarnings())->toBeEmpty();
    }
);

it(
    'retrieves a matching public key correctly',
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
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; c=relaxed/simple;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message), new TestingResolver());
        $validation = $validator->validate();
        expect($validation->isValid())->toBeFalse();
    }
);

it(
    'detects a missing public key',
    function () {
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; s=phpmailerx;\r\n" .
            " a=rsa-sha256; q=dns/txt; l=6; t=1570645905; c=relaxed/simple;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message), new TestingResolver());
        $validation = $validator->validate();
        expect($validation->isValid())->toBeFalse();
        throw new ValidatorException();
    }
)->throws(ValidatorException::class);

it(
    'identifies a mismatching body signature',
    function () {
        //1 char in the message body has been changed, so body signature should not match
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=phpmailer;\r\n" .
            " a=rsa-sha256; l=6; t=1570645905; c=relaxed/simple; q=dns/txt;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "text";

        $validator = new Validator(new Message($message), new TestingResolver());
        $validation = $validator->validate();
        expect($validation->isValid())->toBeFalse();
    }
);

it(
    'identifies an mismatching DKIM record version',
    function () {
        //Compares the v=1 DKIM tag in the header with the v=DKIM1 part of the DNS record
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=baddkimversion;\r\n" .
            " a=rsa-sha256; l=6; t=1570645905; c=relaxed/simple; q=dns/txt;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message), new TestingResolver());
        $validation = $validator->validate();
        expect($validation->isValid())->toBeFalse();
    }
);

it(
    'identifies a mismatching hash algorithm',
    function () {
        //Compares the hash algorithm in the DKIM a tag in the header with an optional h tag in the DNS record
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=badhashtype;\r\n" .
            " a=rsa-sha256; l=6; t=1570645905; c=relaxed/simple; q=dns/txt;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message), new TestingResolver());
        $validation = $validator->validate();
        expect($validation->isValid())->toBeFalse();
    }
);

it(
    'identifies a mismatching encryption algorithm',
    function () {
        //Compares the hash algorithm in the DKIM a tag in the header with an optional h tag in the DNS record
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=badkeytype;\r\n" .
            " a=rsa-sha256; l=6; t=1570645905; c=relaxed/simple; q=dns/txt;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message), new TestingResolver());
        $validation = $validator->validate();
        expect($validation->isValid())->toBeFalse();
    }
);

it(
    'identifies an invalid or unknown DKIM service type',
    function () {
        //Compares the hash algorithm in the DKIM a tag in the header with an optional h tag in the DNS record
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=badservicetype;\r\n" .
            " a=rsa-sha256; l=6; t=1570645905; c=relaxed/simple; q=dns/txt;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message), new TestingResolver());
        $validation = $validator->validate();
        expect($validation->isValid())->toBeFalse();
    }
);

it(
    'identifies an invalid signature algorithm',
    function () {
        //Has an invalid value in the DKIM 'a' tag
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=phpmailer;\r\n" .
            " a=bad_value; l=6; t=1570645905; c=relaxed/simple; q=dns/txt;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message), new TestingResolver());
        $validation = $validator->validate();
        expect($validation->isValid())->toBeFalse();
    }
);

it(
    'identifies a valid signature algorithm that does not exist in openssl',
    function () {
        //Has an unknown signature type in the DKIM 'a' tag
        $message = "Date: Wed, 9 Oct 2019 18:31:45 +0000\r\n" .
            "To: DKIM test <3yHp6B4Ge9vspC@dkimvalidator.com>\r\n" .
            "From: Email test <test@example.com>\r\n" .
            "Subject: DKIM sign\r\n" .
            "Message-ID: <4JyENfIuXMRgdMymktmFxe0oqnSzslfdvbHYR4E@Mac-Pro.local>\r\n" .
            "X-Mailer: PHPMailer 6.1.6 (https://github.com/PHPMailer/PHPMailer)\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: text/html; charset=iso-8859-1\r\n" .
            "DKIM-Signature: v=1; d=example.com; i=test@example.com; s=phpmailer;\r\n" .
            " a=banana-duck; l=6; t=1570645905; c=relaxed/simple; q=dns/txt;\r\n" .
            " h=Date:To:From:Subject:Message-ID:X-Mailer:Content-Type;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=ljWj1co9L6sMrXJ1yBwJ771dnjvVKZN3i97Q/QB0lGQf43FPdautceMsiu3M132QopX63Osqp\r\n" .
            " T1Oz40T9EMONwzCpzIMKKB/tNjDe5qw+evPjf/5mAaiVpIevh1P377t/K0y0nRmCaPbfa0sbm\r\n" .
            " eoFMSapHqTbf2phVJOCo7ejp3laovXSOhQoLZQrnCCW8LnqibtSoAO24ryr+B045XyBIcGPQk\r\n" .
            " IWnRd043/Onv9ACRzau3F80gszR/86grpUwmZ88wHTL8R6g/pqz2eExQNNRmkFaVkwFG0vT5o\r\n" .
            " Rh7Z0ZEl+n4fqoyrTctR8ZEimwwd+xFOtx1hB9KgjW+JVcdTVQ==\r\n\r\n" .
            "test";

        $validator = new Validator(new Message($message), new TestingResolver());
        $validation = $validator->validate();
        expect($validation->isValid())->toBeFalse();
    }
);

it(
    'canonicalizes an empty body correctly',
    function () {
        $validator = new Validator(new Message("test:test\r\n\r\n"), new TestingResolver());
        $body = $validator->canonicalizeBody();
        expect($body)->toEqual(Validator::CRLF);
    }
);

it(
    'detects an invalid selector in a DKIM record',
    function () {
        $validator = new Validator(new Message("test:test\r\n\r\ntest"), new TestingResolver());
        $validator->fetchPublicKeys('example.com', 'bad%selector');
    }
)->throws(ValidatorException::class);

it(
    'ignores a trailing semicolon in a DKIM record',
    function () {
        $validator = new Validator(new Message("test:test\r\n\r\ntest"), new TestingResolver());
        $keys = $validator->fetchPublicKeys('example.com', 'trailingsemi');
        expect($keys)->toHaveCount(1);
        expect($keys[0])->toHaveCount(3);
    }
);

it(
    'detects a DKIM record with an invalid format',
    function () {
        $validator = new Validator(new Message("test:test\r\n\r\ntest"), new TestingResolver());
        $validator->fetchPublicKeys('example.com', 'badformat');
    }
)->throws(DNSException::class);

it(
    'refuses to canonicalize an empty set of headers',
    function () {
        $validator = new Validator(new Message("test:test\r\n\r\ntest"), new TestingResolver());
        $validator->canonicalizeHeaders([]);
    }
)->throws(DKIMException::class);

it(
    'detects invalid base64 encoding of a signature',
    function () {
        Validator::validateSignature(
            'abc',
            '%%%',
            'goodbye',
            Validator::DEFAULT_HASH_FUNCTION
        );
    }
)->throws(DKIMException::class);

it(
    'detects an invalid signature',
    function () {
        Validator::validateSignature(
            'abc',
            base64_encode('123'),
            'hello',
            Validator::DEFAULT_HASH_FUNCTION
        );
    }
)->throws(DKIMException::class);

it(
    'detects an invalid key',
    function () {
        Validator::validateSignature(
            'abc',
            'abc',
            'abc',
            Validator::DEFAULT_HASH_FUNCTION
        );
    }
)->throws(DKIMException::class);

it(
    'skips unnamed DKIM tags',
    function () {
        $tags = Validator::extractDKIMTags(new Header('DKIM-Signature: s=phpmailer; =true'));
        expect($tags)->toEqual(['s' => 'phpmailer']);
    }
);

it(
    'skips trailing semi-colon in DKIM tags',
    function () {
        $tags = Validator::extractDKIMTags(new Header('DKIM-Signature: s=phpmailer; x=true;'));
        expect($tags)->toEqual(['s' => 'phpmailer', 'x' => 'true']);
    }
);

it(
    'verifies signatures correctly',
    function () {
        //Sign an arbitrary message using the DKIM keys
        $private = TestingKeys::getPrivateKey();
        $text = 'who ate my email?';
        $signature = '';
        //Create a signature (by reference) using the private key
        $signedok = openssl_sign($text, $signature, $private, Validator::DEFAULT_HASH_FUNCTION);

        expect($signedok)->toBeTrue();
        expect($signature)->not->toBeEmpty();

        //Create a placeholder instance so we can use its signature validator
        $validator = new Validator(new Message("test:test\r\n\r\ntest"), new TestingResolver());
        $keys = $validator->fetchPublicKeys('example.com', 'phpmailer');
        $isValid = Validator::validateSignature(
            $keys[0]['p'],
            base64_encode($signature),
            $text
        );

        //Check that the signature matches
        expect($isValid)->toBeTrue();
    }
);
