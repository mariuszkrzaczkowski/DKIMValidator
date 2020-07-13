<?php

namespace PHPMailer\DKIMValidator;

class Resolver implements ResolverInterface
{
    /**
     * @param string $domain
     *
     * @return array
     * @throws DNSException
     */
    public function getTextRecords(string $domain): array
    {
        return dns_get_record($domain, DNS_TXT);
    }
}
