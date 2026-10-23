<?php
namespace pmill\AwsCognito\Exception;

use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Exception;
use Throwable;

class CognitoResponseException extends Exception
{
    /**
     * CognitoResponseException constructor.
     * @param Throwable|null $previous
     */
    public function __construct(?Throwable $previous = null)
    {
        // self::class keeps the message get_class() produced (the declaring class), without the PHP 8.3 deprecation
        parent::__construct(self::class, 0, $previous);
    }

    /**
     * @param CognitoIdentityProviderException $e
     * @return Exception
     */
    public static function createFromCognitoException(Exception $e)
    {
        //If the class is CognitoIdentityProviderException, perform this custom logic
        //to get the actual AWS error
        if (method_exists($e, 'getAwsErrorCode')) {
            $errorClass = "pmill\\AwsCognito\\Exception\\" . $e->getAwsErrorCode();

            if (class_exists($errorClass)) {
                return new $errorClass($e);
            }
        }

        //Otherwise just return the Exception as is
        return $e;
    }
}
