<?php

namespace Yomafleet\CognitoAuthenticator\Contracts;

interface CanGetSubContract
{
    /**
     * get "sub" from request header.
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException
     * @return string
     */
    public function getSub();
}
