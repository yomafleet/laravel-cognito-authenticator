<?php

namespace Yomafleet\CognitoAuthenticator\Contracts;

use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;

interface DecodeTokenContract
{
    /**
     * Decode some token.
     *
     * @return TokenContract
     */
    public function decode(): TokenContract;
}
