<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

class ValidationResult
{
    /**
     * @var bool Whether this validation has passed or not
     */
    public $valid = true;

    /**
     * @var string[] A list of tests that passed
     */
    public $passedTests = [];

    /**
     * @var string[] A list of tests that failed
     */
    public $failedTests = [];

    /**
     * @var string[] A list of tests that generated warnings (non-fatal errors)
     */
    public $warnings = [];

    /**
     * @var string The domain that this test was run for
     */
    public $domain = '';

    /**
     * @var string The DKIM selector that was used for this validation
     */
    public $selector = '';

    /**
     * ValidationResult constructor.
     */
    public function __construct()
    {
    }

    public function isValid(): bool
    {
        return $this->valid;
    }

    public function getPassedTests(): array
    {
        return $this->passedTests;
    }

    public function getFailedTests(): array
    {
        return $this->failedTests;
    }

    public function getWarnings(): array
    {
        return $this->warnings;
    }

    public function getDomain(): string
    {
        return $this->domain;
    }

    public function getSelector(): string
    {
        return $this->selector;
    }

    /**
     * Store the domain that this signature is for.
     *
     * @param string $domain
     */
    public function setDomain(string $domain)
    {
        $this->domain = $domain;
    }

    /**
     * Store the selector used for this validation.
     *
     * @param string $selector
     */
    public function setSelector(string $selector)
    {
        $this->selector = $selector;
    }

    /**
     * @param string $message
     */
    public function addFailedTest(string $message): void
    {
        //If we failed a test, this validation is invalid overall
        $this->valid = false;
        $this->failedTests[] = $message;
    }

    /**
     * @param string $message
     */
    public function addPassedTest(string $message): void
    {
        $this->passedTests[] = $message;
    }

    /**
     * @param string $message
     */
    public function addWarning(string $message): void
    {
        $this->warnings[] = $message;
    }
}
