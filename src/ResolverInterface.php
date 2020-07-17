<?php

namespace PHPMailer\DKIMValidator;

interface ResolverInterface
{
    public static function getTextRecords(string $domain): array;
}
