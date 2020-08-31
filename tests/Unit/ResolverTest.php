<?php

declare(strict_types=1);

use PHPMailer\DKIMValidator\Resolver;

it(
    'retrieves a text record successfully',
    function () {
        $records = Resolver::getTextRecords('gmail.com');
        expect($records)->not->toBeEmpty();
    }
);

it(
    'returns an empty array for a non-existent DKIM record',
    function () {
        $records = Resolver::getTextRecords('asdfghjkl._domainkey.example.com');
        expect($records)->toEqual([]);
    }
);

it(
    'returns an empty array for a non-existent domain',
    function () {
        $records = Resolver::getTextRecords('ml8Mkf0B5YSDlbkGyIgbx2ucrJDTu24HatYnSGaoCezL1e4MHN.museum');
        expect($records)->toEqual([]);
    }
);

it(
    'returns an empty array for an empty domain',
    function () {
        $records = Resolver::getTextRecords('');
        expect($records)->toEqual([]);
    }
);

it(
    'returns an empty array for an invalid domain',
    function () {
        $records = Resolver::getTextRecords('.asdfghjkl._domainkey.example.com');
        expect($records)->toEqual([]);
    }
);
