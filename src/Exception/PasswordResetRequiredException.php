<?php
namespace pmill\AwsCognito\Exception;

use Throwable;

class PasswordResetRequiredException extends \Exception
{
    /**
     * PasswordResetRequiredException constructor.
     * @param Throwable|null $previous
     */
    public function __construct(?Throwable $previous = null)
    {
        // self::class keeps the message get_class() produced (the declaring class), without the PHP 8.3 deprecation
        parent::__construct(self::class, 0, $previous);
    }
}
