<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

interface ResolverInterface
{
    /**
     * @param string $domain
     *
     * @return string[]
     */
    public static function getTextRecords(string $domain): array;
}
