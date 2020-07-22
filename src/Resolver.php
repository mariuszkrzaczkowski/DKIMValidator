<?php

declare(strict_types=1);

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
        //FILTER_FLAG_HOSTNAME may not be entirely correct as it permits _ in hostnames, though that's needed for DKIM
        if (!filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return [];
        }
        $records = dns_get_record($domain, DNS_TXT);
        $txtRecords = [];
        if ($records !== false) {
            foreach ($records as $record) {
                //If the record was split into multiple strings, this element will contain a merged version
                if (array_key_exists('txt', $record)) {
                    $txtRecords[] = $record['txt'];
                }
            }
        }

        return $txtRecords;
    }
}
