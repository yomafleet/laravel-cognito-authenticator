<?php

namespace Yomafleet\CognitoAuthenticator\Factories;

use Yomafleet\CognitoAuthenticator\JwtDecoder;
use Yomafleet\CognitoAuthenticator\CognitoClaimVerifier;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderContract;
use Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract;
use Yomafleet\CognitoAuthenticator\Contracts\ClaimVerifierContract;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderFactoryContract;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolFactoryContract;

class DecoderFactory implements DecoderFactoryContract
{
    /** @var array */
    protected array $clientIds;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\UserPoolFactoryContract */
    protected $userPoolFactory;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract */
    protected $tokenFactory;

    public function __construct(
        array $clientIds,
        UserPoolFactoryContract $userPoolFactory,
        TokenFactoryContract $tokenFactory,
    ) {
        $this->clientIds = $clientIds;
        $this->userPoolFactory = $userPoolFactory;
        $this->tokenFactory = $tokenFactory;
    }

    public function create(): DecoderContract
    {
        return new JwtDecoder($this->createVerifier(), $this->tokenFactory);
    }

    /**
     * Create new verifier by given client-ids
     *
     * @return \Yomafleet\CognitoAuthenticator\Contracts\ClaimVerifierContract
     */
    protected function createVerifier(): ClaimVerifierContract
    {
        $pool = $this->userPoolFactory->create($this->clientIds);
        return new CognitoClaimVerifier($pool);
    }
}
