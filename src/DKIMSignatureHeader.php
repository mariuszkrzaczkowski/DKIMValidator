<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

final class DKIMSignatureHeader extends Header
{
    /**
     * Extract DKIM parameters from a DKIM signature header value.
     *
     * @return array
     */
    public function extractDKIMTags(): array
    {
        $dkimTags = explode(';', $this->stripInternalSpaces());
        //Drop an empty last element caused by a trailing semi-colon
        if (end($dkimTags) === '') {
            array_pop($dkimTags);
        }
        foreach ($dkimTags as $tagIndex => $tagContent) {
            [$tagName, $tagValue] = explode('=', trim($tagContent), 2);
            unset($dkimTags[$tagIndex]);
            if ($tagName === '') {
                continue;
            }
            $dkimTags[$tagName] = $tagValue;
        }

        return $dkimTags;
    }

    /**
     * Remove all whitespace from a string.
     *
     * @return string
     */
    private function stripInternalSpaces(): string
    {
        return preg_replace('/\s+/', '', $this->getUnfoldedValue());
    }
}
