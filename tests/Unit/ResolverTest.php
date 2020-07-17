<?php

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
