<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

class Header
{
    /**
     * RFC822 line break sequence
     */
    private const CRLF = "\r\n";

    /**
     * String used as folding white space
     */
    private const FWS = ' ';

    /**
     * @var string Raw original text of a header, including label, line breaks and FWS
     */
    private $raw;
    /**
     * @var string The header label
     */
    private $name;
    /**
     * @var string The raw
     */
    private $value;

    /**
     * Header constructor.
     *
     * @param string $header A complete single header including line breaks and any FWS
     *
     * @throws HeaderException
     */
    public function __construct(string $header)
    {
        $this->raw = $header;
        $headerLines = explode(self::CRLF, $header);
        $headerLineIndex = 0;
        $currentHeaderLabel = '';
        $currentHeaderValue = '';
        $matches = [];
        foreach ($headerLines as $headerLine) {
            if (preg_match('/^([^ \t]*?)[ \t]*(?::[ \t]*)(.*)$/', $headerLine, $matches)) {
                //This is a line that does not start with FWS, so it's the start of a new header
                $currentHeaderLabel = $matches[1];
                $currentHeaderValue = $matches[2];
            } elseif (preg_match('/^[ \t]+(.*)$/', $headerLine, $matches)) {
                //This line starts with FWS, so it should be a folded continuation of the current header
                if ($headerLineIndex === 0) {
                    throw new HeaderException('Invalid header starting with a folded line');
                }

                $currentHeaderValue .= $matches[1];
            }
            ++$headerLineIndex;
        }
        $this->name = $currentHeaderLabel;
        $this->value = $currentHeaderValue;
    }

    /**
     * Get the header label only.
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Get the header value including unfolding.
     *
     * @return string
     */
    public function getValue(): string
    {
        return $this->value;
    }

    /**
     * Return the the header value with any RFC2047 encoding removed.
     *
     * @return string
     */
    public function getDecodedValue(): string
    {
        if (strpos($this->value, '=?') !== 0) {
            //The header does not appear to be encoded, so return raw value instead
            return $this->value;
        }

        return mb_decode_mimeheader($this->value);
    }

    /**
     * Return a whole header canonicalized according to the `relaxed` scheme.
     *
     * @see https://tools.ietf.org/html/rfc6376#section-3.4.2
     *
     * @return string
     */
    public function getRelaxedCanonicalizedHeader(): string
    {
        //Lowercase and trim header name
        $name = trim($this->getLowerLabel());

        //Unfold, collapse whitespace to a single space, and trim
        $val = trim((string) preg_replace('/\s+/', self::FWS, $this->getUnfoldedValue()), " \r\n\t");

        //Stick it back together including a trailing break, note no space before or after the `:`
        return "${name}:${val}" . self::CRLF;
    }

    /**
     * Get the header label in lower case.
     *
     * @return string
     */
    public function getLowerLabel(): string
    {
        return strtolower($this->name);
    }

    /**
     * Unfold a header value, replacing line breaks and FWS with a single space.
     *
     * @return string
     */
    public function getUnfoldedValue(): string
    {
        //Unfold header value
        return preg_replace('/\r\n[ \t]+/', self::FWS, $this->value);
    }

    /**
     * Return a whole header canonicalized according to the `simple` scheme.
     * This involves doing nothing at all!
     *
     * @see https://tools.ietf.org/html/rfc6376#section-3.4.1
     *
     * @return string
     */
    public function getSimpleCanonicalizedHeader(): string
    {
        return $this->getRaw();
    }

    /**
     * Get the entire untouched header, including its label and any folded lines.
     *
     * @return string
     */
    public function getRaw(): string
    {
        return $this->raw;
    }
}
