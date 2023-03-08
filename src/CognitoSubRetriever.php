<?php

namespace Yomafleet\CognitoAuthenticator;

use Illuminate\Http\Request;
use Yomafleet\CognitoAuthenticator\Actions\GetSubAction;
use Yomafleet\CognitoAuthenticator\Contracts\CanGetSubContract;
use Yomafleet\CognitoAuthenticator\Exceptions\AuthorizationHeaderNotFoudException;

class CognitoSubRetriever implements CanGetSubContract
{
    /** @var \Illuminate\Http\Request */
    protected $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * get "sub" from request header.
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException
     * @return string
     */
    public function getSub()
    {
        $getSub = new GetSubAction($this->getBearer());

        return $getSub();
    }

    /**
     * Retrieve 'Authorization' header from request header.
     *
     * @return string
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\AuthorizationHeaderNotFoudException
     */
    public function retrieveAuthHeader()
    {
        $authorization = $this->request->header('authorization');

        if (! $authorization) {
            throw new AuthorizationHeaderNotFoudException();
        }

        return $authorization;
    }

    /**
     * Get Bearer token for authroization header
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\AuthorizationHeaderNotFoudException
     * @return string
     */
    protected function getBearer(): string
    {
        $authorization = $this->retrieveAuthHeader();

        return trim(str_ireplace('Bearer ', '', $authorization));
    }
}
