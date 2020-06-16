<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

class HeaderFactory
{
    /**
     * @param string $rawHeader
     *
     * @return Header|DKIMSignatureHeader
     *
     * @throws HeaderException
     */
    public static function create(string $rawHeader)
    {
        $header = new Header($rawHeader);
        if ($header->getLowerLabel() === 'dkim-signature') {
            //@todo this is inefficient
            $header = new DKIMSignatureHeader($rawHeader);
        }

        return $header;
    }
}
