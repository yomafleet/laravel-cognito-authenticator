<?php

namespace Yomafleet\CognitoAuthenticator\Exceptions;

use Throwable;
use RuntimeException;

class UnauthorizedException extends RuntimeException
{
    protected $message = 'Unauthorized.';

    public function __construct($message = '', int $code = 0, Throwable $previous = null)
    {
        if ($message) {
            $this->message = $message;
        }

        parent::__construct($this->message, $code, $previous);
    }
}
