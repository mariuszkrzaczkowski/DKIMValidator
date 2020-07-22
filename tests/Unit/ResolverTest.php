<?php

declare(strict_types=1);

use PHPMailer\DKIMValidator\Resolver;

it(
    'retrieves a text record successfully',
    function () {
        $records = Resolver::getTextRecords('gmail.com');
        assertNotEmpty($records);
    }
);

it(
    'returns an empty array for a non-existent DKIM record',
    function () {
        $records = Resolver::getTextRecords('asdfghjkl._domainkey.example.com');
        assertEquals([], $records);
    }
);

it(
    'returns an empty array for a non-existent domain',
    function () {
        $records = Resolver::getTextRecords('ml8Mkf0B5YSDlbkGyIgbx2ucrJDTu24HatYnSGaoCezL1e4MHN.museum');
        assertEquals([], $records);
    }
);

it(
    'returns an empty array for an empty domain',
    function () {
        $records = Resolver::getTextRecords('');
        assertEquals([], $records);
    }
);

it(
    'returns an empty array for an invalid domain',
    function () {
        $records = Resolver::getTextRecords('asdfg%hjkl._domainkey.example.com');
        assertEquals([], $records);
    }
);
