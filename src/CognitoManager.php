<?php

namespace Yomafleet\CognitoAuthenticator;

use Illuminate\Http\Request;
use Yomafleet\CognitoAuthenticator\CognitoSubRetriever;
use Yomafleet\CognitoAuthenticator\Factories\TokenFactory;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderContract;
use Yomafleet\CognitoAuthenticator\Factories\UserPoolFactory;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Yomafleet\CognitoAuthenticator\Actions\AuthenticateAction;
use Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract;
use Yomafleet\CognitoAuthenticator\Contracts\ClaimVerifierContract;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolFactoryContract;
use Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException;

class CognitoManager
{

    protected array $clientIds;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\UserPoolFactoryContract */
    protected $userPoolFactory;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract */
    protected $tokenFactory;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\ClaimVerifierContract */
    protected $verifier;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\DecoderContract */
    protected $decoder;

    public function __construct(
        array $clientIds = [''],
        UserPoolFactoryContract $userPoolFactory = null,
        TokenFactoryContract $tokenFactory = null
    ) {
        $this->clientIds = $clientIds;
        $this->userPoolFactory = $userPoolFactory ?: new UserPoolFactory();
        $this->tokenFactory = $tokenFactory ?: new TokenFactory();
        $this->verifier = $this->createVerifier($clientIds);
        $this->decoder = $this->createJwtDecoder();
    }

    /**
     * Create new verifier by given client-ids
     *
     * @param array $clientIds
     * @return ClaimVerifierContract
     */
    protected function createVerifier(array $clientIds): ClaimVerifierContract
    {
        $pool = $this->userPoolFactory->create($clientIds);
        return new CognitoClaimVerifier($pool);
    }

    /**
     * Create new JWT decoder by given clent-ids
     *
     * @return \Yomafleet\CognitoAuthenticator\JwtDecoder
     */
    protected function createJwtDecoder(): JwtDecoder
    {
        return new JwtDecoder($this->verifier, $this->tokenFactory);
    }

    /**
     * Get decoder
     *
     * @return \Yomafleet\CognitoAuthenticator\Contracts\DecoderContract
     */
    public function getDecoder(): DecoderContract
    {
        return $this->decoder;
    }

    /**
     * Get cognito 'sub' retriever
     *
     * @param \Illuminate\Http\Request $request
     * @param \Yomafleet\CognitoAuthenticator\Contracts\DecoderContract|null $decoder
     * @return \Yomafleet\CognitoAuthenticator\CognitoSubRetriever
     */
    public function getSubRetriever(
        Request $request,
        DecoderContract $decoder = null
    ): CognitoSubRetriever {
        if (! is_a($decoder, DecoderContract::class)) {
            $decoder = $this->decoder;
        }

        return new CognitoSubRetriever($request, $decoder);
    }

    /**
     * Authenticate via cognito
     *
     * @param string $identifier
     * @param string $password
     * @return array
     */
    public function authenticate($identifier, $password)
    {
        $poolId = config('cognito.pool_id');
        $clientId = config('cognito.id');
        $clientSecret = config('cognito.secret');
        $credentials = config('cognito.credentials');
        $client = new CognitoIdentityProviderClient($credentials + [
            'region' => config('cognito.region'),
            'version' => config('cognito.version')
        ]);
        $authenticateAction = new AuthenticateAction(
            new CognitoAuthenticator($client, $poolId, $clientId, $clientSecret)
        );

        $response = $authenticateAction($identifier, $password);

        if (! $response || ! method_exists($response, 'toArray')) {
            throw new UnauthorizedException("Unauthorized!");
        }

        $result = $response->toArray();

        if (! array_key_exists('AuthenticationResult', $result)) {
            throw new UnauthorizedException("Unauthorized!");
        }

        $result = $result['AuthenticationResult'];

        return [
            'access_token' => $result['AccessToken'],
            'expires_in' => $result['ExpiresIn'],
            'refresh_token' => $result['RefreshToken'],
            'id_token' => $result['IdToken'],
        ];
    }
}
