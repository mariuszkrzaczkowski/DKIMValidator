<?php

namespace PHPMailer\DKIMValidator\Tests;

use PHPMailer\DKIMValidator\ResolverInterface;

class TestingResolver implements ResolverInterface
{
    /**
     * Get faked DNS records for testing purposes.
     *
     * @param string $domain
     *
     * @return array
     */
    public static function getTextRecords(string $domain): array
    {
        switch ($domain) {
            case 'phpmailer._domainkey.example.com':
                return TestingKeys::getPublicKeyInDNSFormat(true);
            case 'baddkimversion._domainkey.example.com':
                $record = TestingKeys::getPublicKeyInDNSFormat(true);

                return [str_replace('v=DKIM1', 'v=DKIM2', $record[0])];
            case 'badhashtype._domainkey.example.com':
                $record = TestingKeys::getPublicKeyInDNSFormat(true);

                return [str_replace('k=rsa', 'k=rsa; h=md5', $record[0])];
            case 'badkeytype._domainkey.example.com':
                $record = TestingKeys::getPublicKeyInDNSFormat(true);

                return [str_replace('k=rsa', 'k=lawnmower', $record[0])];
            case 'badservicetype._domainkey.example.com':
                $record = TestingKeys::getPublicKeyInDNSFormat(true);

                return [str_replace('k=rsa', 'k=rsa; s=custard', $record[0])];
            default:
                return [];
        }
    }
}
