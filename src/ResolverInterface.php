<?php

namespace PHPMailer\DKIMValidator;

interface ResolverInterface
{
    public function getTextRecords(string $domain): array;
}
