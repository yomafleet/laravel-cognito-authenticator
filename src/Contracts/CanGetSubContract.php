<?php

namespace Yomafleet\CognitoAuthenticator\Contracts;

interface CanGetSubContract
{
    /**
     * Get "sub" from the token.
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException
     * @return string
     */
    public function getSub();
}
