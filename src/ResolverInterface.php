<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

interface ResolverInterface
{
    public static function getTextRecords(string $domain): array;
}
