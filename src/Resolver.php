<?php

namespace PHPMailer\DKIMValidator;

class Resolver implements ResolverInterface
{
    /**
     * @param string $domain
     *
     * @return array
     */
    public static function getTextRecords(string $domain): array
    {
        $records = dns_get_record($domain, DNS_TXT);
        if ($records === false) {
            return [];
        }
        return $records;
    }
}
