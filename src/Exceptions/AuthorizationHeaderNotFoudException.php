<?php

namespace Yomafleet\CognitoAuthenticator\Exceptions;

use Throwable;
use RuntimeException;

class AuthorizationHeaderNotFoudException extends RuntimeException
{
    protected $message = 'Authorization header not found.';

    public function __construct($message = '', int $code = 0, Throwable $previous = null)
    {
        if ($message) {
            $this->message = $message;
        }

        parent::__construct($this->message, $code, $previous);
    }

}
