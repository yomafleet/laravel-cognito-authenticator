<?php

namespace Yomafleet\CognitoAuthenticator;

use Mockery;
use Illuminate\Http\Request;
use Yomafleet\CognitoAuthenticator\CognitoSubRetriever;
use Yomafleet\CognitoAuthenticator\CognitoAuthenticator;
use Yomafleet\CognitoAuthenticator\Factories\TokenFactory;
use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;
use Yomafleet\CognitoAuthenticator\Factories\DecoderFactory;
use Yomafleet\CognitoAuthenticator\Actions\DecodeTokenAction;
use Yomafleet\CognitoAuthenticator\Factories\UserPoolFactory;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Yomafleet\CognitoAuthenticator\Actions\AuthenticateAction;
use Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderFactoryContract;
use Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolFactoryContract;

class CognitoManager
{

    /** @var array */
    protected array $clientIds;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\UserPoolFactoryContract */
    protected $userPoolFactory;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract */
    protected $tokenFactory;

    /** @var \Yomafleet\CognitoAuthenticator\CognitoSubRetriever */
    public $subRetriever;

    public function __construct(
        array $clientIds = [''],
        UserPoolFactoryContract $userPoolFactory = null,
        TokenFactoryContract $tokenFactory = null,
        CognitoSubRetriever $subRetriever = null,
    ) {
        $this->clientIds = $clientIds;
        $this->userPoolFactory = $userPoolFactory ?: new UserPoolFactory();
        $this->tokenFactory = $tokenFactory ?: new TokenFactory();

        if ($subRetriever) {
            $this->subRetriever = $subRetriever;
        }
    }
    
    /**
     * Set the userpool factory
     *
     * @param UserPoolFactoryContract $userPoolFactory
     * @return void
     */
    public function setUserPoolFactory(UserPoolFactoryContract $userPoolFactory)
    {
        $this->userPoolFactory = $userPoolFactory;
    }

    /**
     * Set cognito "sub" retriever
     *
     * @param CognitoSubRetriever $subRetriever
     * @return void
     */
    public function setCognitoSubRetriever(CognitoSubRetriever $subRetriever)
    {
        $this->subRetriever = $subRetriever;
    }

    /**
     * Get decoder factory
     *
     * @return \Yomafleet\CognitoAuthenticator\Contracts\DecoderFactoryContract
     */
    public function getDecoderFactory(): DecoderFactoryContract
    {
        return new DecoderFactory($this->clientIds, $this->userPoolFactory, $this->tokenFactory);
    }

    /**
     * Decode a given Bearer token
     *
     * @param string $token
     * @return \Yomafleet\CognitoAuthenticator\Contracts\TokenContract
     */
    public function decode($token)
    {
        $decoderFactory = $this->getDecoderFactory();
        $decode = new DecodeTokenAction($token, $decoderFactory->create());

        return $decode();
    }

    /**
     * Get cognito 'sub' retriever
     *
     * @param \Illuminate\Http\Request $request
     * @return \Yomafleet\CognitoAuthenticator\CognitoSubRetriever
     */
    public function getSubRetriever(Request $request)
    {
        if ($this->subRetriever) {
            return $this->subRetriever;
        }

        $this->subRetriever = $this->createSubRetriever($request);

        return $this->subRetriever;
    }

    /**
     * Create cognito 'sub' retriever
     *
     * @param \Illuminate\Http\Request $request
     * @param \Yomafleet\CognitoAuthenticator\Contracts\DecoderContract|null $decoder
     * @return \Yomafleet\CognitoAuthenticator\CognitoSubRetriever
     */
    public function createSubRetriever(
        Request $request,
        DecoderFactoryContract $decoderFactory = null
    ): CognitoSubRetriever {
        if (! is_a($decoderFactory, DecoderFactoryContract::class)) {
            $decoderFactory = $this->getDecoderFactory();
        }

        return new CognitoSubRetriever($request, $decoderFactory);
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

    /**
     * Set the current user for the application.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable|\Yomafleet\CognitoAuthenticator\Traits\HasCognitoSub $user
     * @param array $jwk
     * @param string $guard
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function actingAs($user, $jwk, $guard = 'api')
    {
        $subRetriever = new class (app('request'), $this->getDecoderFactory()) extends CognitoSubRetriever
        {
            public function getDecoded($tokenType = 'access'): TokenContract
            {
                return (new TokenFactory())->create([
                    "sub" => "6a41dddc-feb1-447a-907a-a47c7e6a872b",
                    "iss" => "https://cognito-idp.ap-southeast-1.amazonaws.com/ap-southeast-1_7g0492XkI",
                    "version" => 2,
                    "client_id" => "57fvb75dd1p93ri66fut2obff4",
                    "origin_jti" => "aa2db77e-d7a6-4720-85a3-736f3bf6287a",
                    "event_id" => "56193124-b5d0-4f92-ab12-cefdf5a34656",
                    "token_use" => $tokenType,
                    "scope" => "openid profile email",
                    "auth_time" => time(),
                    "exp" => time() + 86400,
                    "iat" => time(),
                    "jti" => "f9be0f56-ed46-4dff-8966-513a10ce1d08",
                    "name" => "6a41dddc-feb1-447a-907a-a47c7e6a872b",
                    "email" => "user@example.com",
                ]);
            }
        };

        $manager = app('cognito-authenticator');
        $manager->setUserPoolFactory(new UserPoolFactory($jwk));
        $manager->setCognitoSubRetriever($subRetriever);

        app('auth')->guard($guard)->setUser($user);

        app('auth')->shouldUse($guard);

        return $user;
    }
}
