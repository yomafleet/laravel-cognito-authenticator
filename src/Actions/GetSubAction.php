<?php

namespace Yomafleet\CognitoAuthenticator\Actions;

use Illuminate\Http\Request;
use Yomafleet\CognitoAuthenticator\JwtDecoder;
use Illuminate\Validation\UnauthorizedException;
use Yomafleet\CognitoAuthenticator\Models\UserPool;
use Yomafleet\CognitoAuthenticator\CognitoClaimVerifier;
use Yomafleet\CognitoAuthenticator\Factories\TokenFactory;
use Yomafleet\CognitoAuthenticator\Factories\UserPoolFactory;
use Yomafleet\CognitoAuthenticator\Contracts\CanGetSubContract;
use Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolFactoryContract;
use Yomafleet\CognitoAuthenticator\Exceptions\AuthorizationHeaderNotFoudException;

class GetSubAction implements CanGetSubContract
{
    /** @var \Illuminate\Http\Request */
    protected $request;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\UserPoolFactoryContract */
    protected $userPoolFactory;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract */
    protected $tokenFactory;

    public function __construct(
        Request $request,
        UserPoolFactoryContract $userPoolFactory = null,
        TokenFactoryContract $tokenFactory = null,
    ) {
        $this->request = $request;
        $this->userPoolFactory = $userPoolFactory ?: new UserPoolFactory();
        $this->tokenFactory = $tokenFactory ?: new TokenFactory();
    }

    /**
     * get "sub" from request header.
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException
     * @return string
     */
    public function __invoke(): string
    {
        return $this->getSub();
    }

    /**
     * get "sub" from request header.
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException
     * @return string
     */
    public function getSub(): string
    {
        $pool = $this->getUserPool(['']);
        $decoder = $this->getDecoder($pool);
        $token = $decoder->decode($this->getBearer());

        if (! $token) {
            throw new UnauthorizedException();
        }

        return $token->getSub();
    }

    /**
     * Get Bearer token for authroization header
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\AuthorizationHeaderNotFoudException
     * @return string
     */
    protected function getBearer(): string
    {
        $authorization = $this->request->header('authorization');

        if (! $authorization) {
            throw new AuthorizationHeaderNotFoudException();
        }

        return trim(str_ireplace('Bearer ', '', $authorization));
    }

    /**
     * Get user pool
     *
     * @param array $clientIds
     * @return \Yomafleet\CognitoAuthenticator\Models\UserPool
     */
    protected function getUserPool(array $clientIds): UserPool
    {
        return $this->userPoolFactory->create($clientIds);
    }

    /**
     * Get JWT decoder
     *
     * @param \Yomafleet\CognitoAuthenticator\Models\UserPool $pool
     * @return \Yomafleet\CognitoAuthenticator\JwtDecoder
     */
    protected function getDecoder(UserPool $pool)
    {
        $verifier = new CognitoClaimVerifier($pool);

        return new JwtDecoder($verifier, $this->tokenFactory);
    }
}
