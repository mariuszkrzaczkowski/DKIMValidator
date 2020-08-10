<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

class Validator
{
    /**
     * Carriage return, line feed; the standard RFC822 line break
     */
    public const CRLF = "\r\n";

    /**
     * Line feed character; standard unix line break
     */
    public const LF = "\n";

    /**
     * Carriage return character
     */
    public const CR = "\r";

    /**
     * Default whitespace string
     */
    public const SPACE = ' ';

    /**
     * A regex pattern to validate DKIM selectors
     *
     * @see self::validateSelector() for how this pattern is constructed
     */
    public const SELECTOR_VALIDATION =
        '[a-zA-Z\d](([a-zA-Z\d-])*[a-zA-Z\d])*(\.[a-zA-Z\d](([a-zA-Z\d-])*[a-zA-Z\d])*)*';

    /**
     * Algorithms for header and body canonicalization are constant
     *
     * @see https://tools.ietf.org/html/rfc6376#section-3.4
     */
    public const CANONICALIZATION_BODY_SIMPLE = 'simple';
    public const CANONICALIZATION_BODY_RELAXED = 'relaxed';
    public const CANONICALIZATION_HEADERS_SIMPLE = 'simple';
    public const CANONICALIZATION_HEADERS_RELAXED = 'relaxed';

    public const DEFAULT_HASH_FUNCTION = 'sha256';

    public const STATUS_FAIL_PERMANENT = 'PERMFAIL';
    public const STATUS_FAIL_TEMPORARY = 'TEMPFAIL';
    public const STATUS_SUCCESS_INFO = 'INFO';

    /**
     * @var Message
     */
    protected $message;

    /**
     * An instance used for resolving DNS records.
     *
     * @var ResolverInterface
     */
    protected $resolver;

    /**
     * @var array
     */
    private $publicKeys = [];

    /**
     * Constructor
     *
     * @param Message $message
     * @param ResolverInterface|null $resolver
     */
    public function __construct(Message $message, ResolverInterface $resolver = null)
    {
        $this->message = $message;
        //Injecting a DNS resolver allows this to be pluggable, which also helps with testing
        if ($resolver === null) {
            $this->resolver = new Resolver();
        } else {
            $this->resolver = $resolver;
        }
    }

    /**
     * Get all DKIM signature headers.
     *
     * @return Header[]
     * @throws HeaderException
     */
    protected function getDKIMHeaders(): array
    {
        return $this->message->getHeadersNamed('dkim-signature');
    }

    /**
     * Validation wrapper - return boolean true/false about validation success/failure
     *
     * @return bool
     */
    public function validateBoolean(): bool
    {
        //Execute original validation method
        try {
            $analysis = $this->validate();
        } catch (DKIMException $e) {
            return false;
        } catch (HeaderException $e) {
            return false;
        }

        return (bool)$analysis['valid'];
    }

    /**
     * Validate all DKIM signatures found in the message.
     *
     * @return array
     *
     * @throws DKIMException|HeaderException
     */
    public function validate(): array
    {
        $valid = false;
        $output = [];

        //Find all DKIM signatures amongst the headers (there may be more than one)
        $signatures = $this->getDKIMHeaders();

        //Validate each signature in turn
        foreach ($signatures as $signatureIndex => $signature) {
            //Let's be optimistic!
            $output[$signatureIndex]['valid'] = true;
            try {
                //Split into tags
                $dkimTags = self::extractDKIMTags($signature);

                //Verify all required tags are present
                //http://tools.ietf.org/html/rfc4871#section-6.1.1
                $required = ['v', 'a', 'b', 'bh', 'd', 'h', 's'];
                foreach ($required as $tagIndex) {
                    if (! array_key_exists($tagIndex, $dkimTags)) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_PERMANENT,
                            'reason' => "DKIM signature missing required tag: ${tagIndex}",
                        ];
                        throw new ValidatorException();
                    }

                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => "Required DKIM tag present: ${tagIndex}",
                    ];
                }

                //Validate DKIM version number
                if (array_key_exists('v', $dkimTags) && (int)$dkimTags['v'] !== 1) {
                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => "Incompatible DKIM version: ${dkimTags['v']}",
                    ];
                    throw new ValidatorException();
                }

                $output[$signatureIndex]['analysis'][] = [
                    'status' => self::STATUS_SUCCESS_INFO,
                    'reason' => "Compatible DKIM version: ${dkimTags['v']}",
                ];

                //Validate canonicalization algorithms for header and body
                [$headerCA, $bodyCA] = explode('/', $dkimTags['c']);
                if (
                    $headerCA !== self::CANONICALIZATION_HEADERS_RELAXED &&
                    $headerCA !== self::CANONICALIZATION_HEADERS_SIMPLE
                ) {
                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => "Unknown header canonicalization algorithm: ${headerCA}",
                    ];
                    throw new ValidatorException();
                }
                if (
                    $bodyCA !== self::CANONICALIZATION_BODY_RELAXED &&
                    $bodyCA !== self::CANONICALIZATION_BODY_SIMPLE
                ) {
                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => "Unknown body canonicalization algorithm: ${bodyCA}",
                    ];
                    throw new ValidatorException();
                }

                $output[$signatureIndex]['analysis'][] = [
                    'status' => self::STATUS_SUCCESS_INFO,
                    'reason' => "Valid body canonicalization algorithm: ${bodyCA}",
                ];

                //Canonicalize body
                $canonicalBody = $this->canonicalizeBody($bodyCA);

                //Validate optional body length tag
                //If this is present, the canonical body should be *at least* this long,
                //though it may be longer, which is a minor security risk,
                //so it's common not to use the `l` tag
                if (array_key_exists('l', $dkimTags)) {
                    $bodyLength = strlen($canonicalBody);
                    if ((int)$dkimTags['l'] > $bodyLength) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_PERMANENT,
                            'reason' => 'Body too short: ' . $dkimTags['l'] . '/' . $bodyLength,
                        ];
                        throw new ValidatorException();
                    }

                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => "Optional body length tag is present and valid: ${bodyLength}",
                    ];
                }

                //Ensure the optional user identifier ends in the signing domain
                if (array_key_exists('i', $dkimTags)) {
                    if (substr($dkimTags['i'], -strlen($dkimTags['d'])) !== $dkimTags['d']) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_PERMANENT,
                            'reason' => 'Agent or user identifier does not match domain: ' . $dkimTags['i'],
                        ];
                        throw new ValidatorException();
                    }

                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Agent or user identifier matches domain: ' . $dkimTags['i'],
                    ];
                }

                //Ensure the signature includes the From field
                if (array_key_exists('h', $dkimTags)) {
                    if (stripos($dkimTags['h'], 'From') === false) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_PERMANENT,
                            'reason' => 'From header not included in signed header list: ' . $dkimTags['h'],
                        ];
                        throw new ValidatorException();
                    }

                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'From header is included in signed header list.',
                    ];
                }

                //Validate and check expiry time
                if (array_key_exists('x', $dkimTags)) {
                    if ((int)$dkimTags['x'] < time()) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_PERMANENT,
                            'reason' => 'Signature has expired.',
                        ];
                        throw new ValidatorException();
                    }

                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Signature has not expired',
                    ];
                    if ((int)$dkimTags['x'] < (int)$dkimTags['t']) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_PERMANENT,
                            'reason' => 'Expiry time is before signature time.',
                        ];
                        throw new ValidatorException();
                    }

                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Expiry time is after signature time.',
                    ];
                }

                //The 'q' tag may be empty - add a default value if it is
                if (! array_key_exists('q', $dkimTags) || $dkimTags['q'] === '') {
                    $dkimTags['q'] = 'dns/txt';
                }

                //Fetch public keys from DNS using the domain and selector from the signature
                //May return multiple keys
                [$qType, $qFormat] = explode('/', $dkimTags['q'], 2);
                if ($qType . '/' . $qFormat === 'dns/txt') {
                    try {
                        $dnsKeys = $this->fetchPublicKeys($dkimTags['d'], $dkimTags['s']);
                    } catch (ValidatorException $e) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_TEMPORARY,
                            'reason' => 'Invalid selector: ' . $dkimTags['s'] . ' for domain: ' . $dkimTags['d'],
                        ];
                        throw new ValidatorException();
                    } catch (DNSException $e) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_TEMPORARY,
                            'reason' => 'Public key not found in DNS, skipping signature',
                        ];
                        throw new ValidatorException();
                    }
                    $this->publicKeys[$dkimTags['d']] = $dnsKeys;
                } else {
                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => 'Public key unavailable (unknown q= query format), skipping signature',
                    ];
                    throw new ValidatorException();
                }

                //http://tools.ietf.org/html/rfc4871#section-6.1.3
                //Select signed headers and canonicalize
                $signedHeaderNames = array_unique(explode(':', $dkimTags['h']));
                $headersToCanonicalize = [];
                foreach ($signedHeaderNames as $headerName) {
                    //TODO Deal with duplicate signed header values
                    //and extra blank headers used to force invalidation
                    $matchedHeaders = $this->message->getHeadersNamed($headerName);
                    foreach ($matchedHeaders as $header) {
                        $headersToCanonicalize[] = $header;
                    }
                }
                //Need to remove the `b` value from the signature header before checking the hash
                $headersToCanonicalize[] = new Header(
                    'DKIM-Signature: ' .
                    preg_replace('/b=(.*?)(;|$)/s', 'b=$2', $signature->getValue())
                );

                //Extract the encryption algorithm and hash function and validate according to the
                //https://tools.ietf.org/html/rfc6376#section-3.5 definition of the `a` tag
                $matches = [];
                if (
                    preg_match(
                        '/^(rsa|[a-zA-Z][a-zA-Z\d]*)-(sha1|sha256|[a-zA-Z][a-zA-Z\d]*)$/',
                        $dkimTags['a'],
                        $matches
                    )
                ) {
                    $alg = $matches[1];
                    $hash = $matches[2];
                } else {
                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => '\'a\' tag uses an invalid signature algorithm specifier',
                    ];
                    throw new ValidatorException();
                }

                # Check that the hash algorithm is available in openssl
                if (! in_array($hash, openssl_get_md_methods(true), true)) {
                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => "Signature algorithm ${hash} is not available in" .
                            " openssl",
                    ];
                    throw new ValidatorException();
                }

                //Canonicalize the headers
                $canonicalHeaders = $this->canonicalizeHeaders($headersToCanonicalize, $headerCA);

                //Calculate the body hash
                $bodyHash = self::hashBody($canonicalBody, $hash);

                if (! hash_equals($bodyHash, $dkimTags['bh'])) {
                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => 'Computed body hash does not match signature body hash',
                    ];
                    throw new ValidatorException();
                }

                $output[$signatureIndex]['analysis'][] = [
                    'status' => self::STATUS_SUCCESS_INFO,
                    'reason' => 'Body hash matches signature.',
                ];

                //Iterate over keys
                /** @psalm-suppress MixedAssignment */
                foreach ($this->publicKeys[$dkimTags['d']] as $keyIndex => $publicKey) {
                    //Confirm that pubkey version matches sig version (v=)
                    /** @var string[] $publicKey */
                    /** @psalm-suppress MixedArgument */
                    if (array_key_exists('v', $publicKey) && $publicKey['v'] !== 'DKIM' . $dkimTags['v']) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_PERMANENT,
                            'reason' => 'Public key version does not match signature' .
                                " version (${dkimTags['d']} key #${keyIndex})",
                        ];
                        throw new ValidatorException();
                    }

                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Public key version matches signature.',
                    ];

                    //Confirm that published hash algorithm matches sig hash
                    //The h tag in DKIM DNS records is optional, and defaults to sha256
                    if (array_key_exists('h', $publicKey) && $publicKey['h'] !== $hash) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_PERMANENT,
                            'reason' => 'Public key hash algorithm does not match signature' .
                                " hash algorithm (${dkimTags['d']} key #${keyIndex})",
                        ];
                        throw new ValidatorException();
                    }

                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Public key hash algorithm (' . $hash . ') matches signature.',
                    ];

                    //Confirm that the DNS key type matches the signature key type
                    if (array_key_exists('k', $publicKey) && $publicKey['k'] !== $alg) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_PERMANENT,
                            'reason' => 'Public key type does not match signature' .
                                " key type (${dkimTags['d']} key #${keyIndex})",
                        ];
                        throw new ValidatorException();
                    }

                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Public key type(' . $alg . ') matches signature.',
                    ];

                    //Ensure the service type tag allows email usage
                    if (array_key_exists('s', $publicKey) && $publicKey['s'] !== '*' && $publicKey['s'] !== 'email') {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_PERMANENT,
                            'reason' => 'Public key service type does not permit email usage' .
                                " (${dkimTags['d']} key #${keyIndex}) ${publicKey['s']}",
                        ];
                        throw new ValidatorException();
                    }

                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Public key service type permits email usage.',
                    ];

                    //@TODO check t= flags

                    // Same as the earlier check for the DKIM a tag, but for the DNS record
                    if (! in_array($hash, openssl_get_md_methods(true), true)) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_PERMANENT,
                            'reason' => "Signature algorithm ${hash} is not available in openssl, key #${keyIndex}",
                        ];
                        throw new ValidatorException();
                    }

                    //Validate the signature
                    $validationResult = self::validateSignature(
                        (string)$publicKey['p'],
                        $dkimTags['b'],
                        $canonicalHeaders,
                        $hash
                    );

                    if (! $validationResult) {
                        $output[$signatureIndex]['analysis'][] = [
                            'status' => self::STATUS_FAIL_PERMANENT,
                            'reason' => 'DKIM signature did not verify ' .
                                "(${dkimTags['d']}/${dkimTags['s']} key #${keyIndex})",
                        ];
                        throw new ValidatorException();
                    }

                    $output[$signatureIndex]['analysis'][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'DKIM signature verified successfully!',
                    ];
                }
            } catch (ValidatorException $e) {
                $output[$signatureIndex]['valid'] = false;
            }
            //If *any* signature passes validation, the message is considered valid overall
            if ($output[$signatureIndex]['valid']) {
                $valid = true;
            }
        }

        return [
            'valid'      => $valid,
            'signatures' => $output,
        ];
    }

    /**
     * Canonicalize a message body in either "relaxed" or "simple" modes.
     * Requires a string containing all body content, with an optional byte-length
     *
     * @param string $algorithm 'relaxed' or 'simple' canonicalization algorithm
     * @param int $length Restrict the output length to this to match up with the `l` tag
     *
     * @return string
     */
    public function canonicalizeBody(
        string $algorithm = self::CANONICALIZATION_BODY_RELAXED,
        int $length = 0
    ): string {
        if ($this->message->getBody() === '') {
            return self::CRLF;
        }

        //Convert CRLF to LF breaks for convenience
        $canonicalBody = str_replace(self::CRLF, self::LF, $this->message->getBody());
        if ($algorithm === self::CANONICALIZATION_BODY_RELAXED) {
            //http://tools.ietf.org/html/rfc4871#section-3.4.4
            //Remove trailing space
            $canonicalBody = preg_replace('/[ \t]+$/m', '', $canonicalBody);
            //Replace runs of whitespace with a single space
            $canonicalBody = preg_replace('/[ \t]+/m', self::SPACE, (string)$canonicalBody);
        }
        //Always perform rules for "simple" canonicalization as well
        //http://tools.ietf.org/html/rfc4871#section-3.4.3
        //Remove any trailing empty lines
        $canonicalBody = preg_replace('/\n+$/', '', (string)$canonicalBody);
        //Convert line breaks back to CRLF
        $canonicalBody = str_replace(self::LF, self::CRLF, (string)$canonicalBody);

        //Add last trailing CRLF
        $canonicalBody .= self::CRLF;

        //If we've been asked for a substring, return that, otherwise return the whole body
        return $length > 0 ? substr($canonicalBody, 0, $length) : $canonicalBody;
    }

    /**
     * Fetch the public key(s) for a domain and selector.
     * Return value is usually (records may vary or have optional tags) of the format:
     * [['v' => <DKIM version>, 'k' => <keytype>, 'p' => <key>]*]
     *
     * @param string $domain
     * @param string $selector
     *
     * @return array
     *
     * @throws DNSException
     * @throws ValidatorException
     */
    public function fetchPublicKeys(string $domain, string $selector): array
    {
        if (! self::validateSelector($selector)) {
            throw new ValidatorException('Invalid selector: ' . $selector);
        }
        $host = sprintf('%s._domainkey.%s', $selector, $domain);
        //The resolver takes care of merging if the record has been split into multiple strings
        $textRecords = $this->resolver->getTextRecords($host);

        if ($textRecords === []) {
            throw new DNSException('Domain has no DKIM records in DNS, or fetching them failed');
        }

        $publicKeys = [];
        foreach ($textRecords as $textRecord) {
            //Dismantle the DKIM record
            /** @var string $textRecord */
            $parts = explode(';', trim($textRecord));
            $record = [];
            foreach ($parts as $part) {
                //Last entry will be empty if there is a trailing semicolon, so skip it
                $part = trim($part);
                if ($part === '') {
                    continue;
                }
                if (strpos($part, '=') === false) {
                    throw new DNSException('DKIM TXT record has invalid format');
                }
                [$key, $val] = explode('=', $part, 2);
                $record[$key] = $val;
            }
            $publicKeys[] = $record;
        }

        return $publicKeys;
    }

    /**
     * Validate a DKIM selector.
     * DKIM selectors have the same rules as sub-domain names, as defined in RFC5321 4.1.2.
     * For example `march-2005.reykjavik` is valid.
     *
     * @see https://tools.ietf.org/html/rfc5321#section-4.1.2
     * @see https://tools.ietf.org/html/rfc6376#section-3.1
     *
     * @param string $selector
     *
     * @return bool
     */
    public static function validateSelector(string $selector): bool
    {
        /*
        //From RFC5321 4.1.2
        $let_dig = '[a-zA-Z\d]';
        $ldh_str = '([a-zA-Z\d-])*' . $let_dig;
        $sub_domain = $let_dig . '(' . $ldh_str . ')*';
        //From RFC6376 3.1
        $selectorpat = $sub_domain . '(\.' . $sub_domain . ')*';
        */

        return (bool)preg_match('/^' . self::SELECTOR_VALIDATION . '$/', $selector);
    }

    /**
     * Validate a domain name.
     *
     * @param string $domain
     *
     * @return bool
     */
    public static function validateDomain(string $domain): bool
    {
        //FILTER_FLAG_HOSTNAME may not be entirely correct as it permits _ in hostnames, though that's needed for DKIM
        return (bool)filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
    }

    /**
     * Canonicalize message headers using either `relaxed` or `simple` algorithms.
     * The relaxed algorithm is more complex, but is more robust
     *
     * @see https://tools.ietf.org/html/rfc6376#section-3.4
     *
     * @param Header[] $headers
     * @param string $algorithm 'relaxed' or 'simple'
     *
     * @return string
     *
     * @throws DKIMException
     */
    public function canonicalizeHeaders(
        array $headers,
        string $algorithm = self::CANONICALIZATION_HEADERS_RELAXED
    ): string {
        if (count($headers) === 0) {
            throw new DKIMException('Attempted to canonicalize empty header array');
        }

        $canonical = '';
        switch ($algorithm) {
            case self::CANONICALIZATION_HEADERS_SIMPLE:
                foreach ($headers as $header) {
                    $canonical .= $header->getSimpleCanonicalizedHeader();
                }
                break;
            case self::CANONICALIZATION_HEADERS_RELAXED:
            default:
                foreach ($headers as $header) {
                    $canonical .= $header->getRelaxedCanonicalizedHeader();
                }
                break;
        }

        return $canonical;
    }

    /**
     * Calculate the hash of a message body.
     *
     * @param string $body
     * @param string $hashAlgo Which hash algorithm to use
     *
     * @return string
     */
    protected static function hashBody(string $body, string $hashAlgo = self::DEFAULT_HASH_FUNCTION): string
    {
        return base64_encode(hash($hashAlgo, $body, true));
    }

    /**
     * Check whether a signed string matches its signature.
     *
     * @param string $publicKeyB64 A base64-encoded public key obtained from DNS
     * @param string $signatureB64 A base64-encoded openssl signature, as found in a DKIM 'b' tag
     * @param string $text The message to verify; usually a canonicalized email message
     * @param string $hashAlgo Any of the algorithms returned by openssl_get_md_methods(), but must be supported by DKIM; usually 'sha256'
     *
     * @return bool
     *
     * @throws DKIMException
     */
    public static function validateSignature(
        string $publicKeyB64,
        string $signatureB64,
        string $text,
        string $hashAlgo = self::DEFAULT_HASH_FUNCTION
    ): bool {
        //Convert key from DNS format into PEM format if its not already wrapped
        $key = $publicKeyB64;
        if (strpos($publicKeyB64, '-----BEGIN PUBLIC KEY-----') !== 0) {
            $key = sprintf(
                "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n",
                trim(chunk_split($publicKeyB64, 64, self::LF))
            );
        }

        $signature = base64_decode($signatureB64, true);
        if ($signature === false) {
            throw new DKIMException('DKIM signature contains invalid base64 data');
        }
        try {
            $verified = openssl_verify($text, $signature, $key, $hashAlgo);
        } catch (\ErrorException $e) {
            //Things like incorrectly formatted keys will trigger this
            throw new DKIMException('Could not verify signature: ' . $e->getMessage());
        }
        if ($verified === 1) {
            return true;
        }
        if ($verified === -1) {
            $message = '';
            //There may be multiple errors; fetch them all
            while ($error = openssl_error_string() !== false) {
                $message .= $error . self::LF;
            }
            throw new DKIMException('OpenSSL verify error: ' . $message);
        }

        return false;
    }

    /**
     * Extract DKIM parameters from a DKIM signature header value.
     *
     * @param Header $header
     *
     * @return string[]
     */
    public static function extractDKIMTags(Header $header): array
    {
        if ($header->getLowerLabel() !== 'dkim-signature') {
            throw new \InvalidArgumentException('Attempted to extract DKIM tags from a non-DKIM header');
        }
        $dkimTags = [];
        //DKIM-Signature headers ignore all internal spaces, which may have been added by folding
        $tagParts = explode(';', $header->getValueWithoutSpaces());
        //Drop an empty last element caused by a (valid) trailing semi-colon
        if (end($tagParts) === '') {
            array_pop($tagParts);
        }
        foreach ($tagParts as $tagIndex => $tagContent) {
            [$tagName, $tagValue] = explode('=', trim($tagContent), 2);
            if ($tagName === '') {
                continue;
            }
            $dkimTags[$tagName] = $tagValue;
        }

        return $dkimTags;
    }

    /**
     * @return Message
     */
    public function getMessage(): Message
    {
        return $this->message;
    }
}
