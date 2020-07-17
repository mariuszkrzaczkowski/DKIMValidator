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
        //Return empty result if the lookup fails
        return $records === false ? [] : $records;
    }
}
