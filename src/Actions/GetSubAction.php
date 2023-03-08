<?php

namespace Yomafleet\CognitoAuthenticator\Actions;

use Yomafleet\CognitoAuthenticator\JwtDecoder;
use Illuminate\Validation\UnauthorizedException;
use Yomafleet\CognitoAuthenticator\Models\UserPool;
use Yomafleet\CognitoAuthenticator\CognitoClaimVerifier;
use Yomafleet\CognitoAuthenticator\Factories\TokenFactory;
use Yomafleet\CognitoAuthenticator\Factories\UserPoolFactory;
use Yomafleet\CognitoAuthenticator\Contracts\CanGetSubContract;
use Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolFactoryContract;

class GetSubAction implements CanGetSubContract
{
    /** @var string */
    protected $authToken;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\UserPoolFactoryContract */
    protected $userPoolFactory;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract */
    protected $tokenFactory;

    public function __construct(
        string $authToken,
        UserPoolFactoryContract $userPoolFactory = null,
        TokenFactoryContract $tokenFactory = null,
    ) {
        $this->authToken = $authToken;
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
        $token = $decoder->decode($this->authToken);

        if (! $token) {
            throw new UnauthorizedException();
        }

        return $token->getSub();
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
