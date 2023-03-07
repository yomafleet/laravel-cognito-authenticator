<?php

namespace Yomafleet\CognitoAuthenticator;

use Illuminate\Http\Request;
use Yomafleet\CognitoAuthenticator\Actions\GetSubAction;
use Yomafleet\CognitoAuthenticator\Contracts\CanGetSubContract;

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
        $getSub = new GetSubAction($this->request);

        return $getSub();
    }
}
