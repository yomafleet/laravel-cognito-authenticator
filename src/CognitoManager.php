<?php

namespace Yomafleet\CognitoAuthenticator;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Yomafleet\CognitoAuthenticator\CognitoConfig;
use Yomafleet\CognitoAuthenticator\Facades\Cognito;
use Yomafleet\CognitoAuthenticator\Models\UserPool;
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
use Yomafleet\CognitoAuthenticator\Models\CognitoUser;

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

    /** @var \Yomafleet\CognitoAuthenticator\PasswordManager */
    protected $passwordManager;

    /** @var \Yomafleet\CognitoAuthenticator\UserManager */
    protected $userManager;

    /** @var string */
    protected $profile;

    public function __construct(
        array $clientIds = [''],
        UserPoolFactoryContract $userPoolFactory = null,
        TokenFactoryContract $tokenFactory = null,
        CognitoSubRetriever $subRetriever = null,
        $profile = null,
    ) {
        $this->clientIds = $clientIds;
        $this->profile($profile ?: CognitoConfig::get('default_profile'));
        $this->userPoolFactory = $userPoolFactory ?: new UserPoolFactory([], $this->profile);
        $this->tokenFactory = $tokenFactory ?: new TokenFactory();

        if ($subRetriever) {
            $this->subRetriever = $subRetriever;
        }
    }

    /**
     * Get the current profile, optionally change while getting it.
     *
     * @param string $name
     * @return string
     */
    public function profile($name = '')
    {
        if ($name) {
            $this->profile = $name;
        }

        return $this->profile;
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
     * @param string $clientProfile
     * @return array
     */
    public function authenticate($identifier, $password, $clientProfile = '')
    {
        $clientConfigs = CognitoConfig::getProfileConfig($clientProfile);
        $poolId = $clientConfigs['pool_id'];
        $clientId = $clientConfigs['id'];
        $clientSecret = $clientConfigs['secret'];
        $client = $this->createCognitoIdentityProviderClient();
        $authenticateAction = new AuthenticateAction(
            new CognitoAuthenticator($client, $poolId, $clientId, $clientSecret)
        );

        $response = $authenticateAction($identifier, $password);

        if (! $response || ! method_exists($response, 'toArray')) {
            throw new UnauthorizedException("Unauthorized!");
        }

        $result = $response->toArray();

        if (
            array_key_exists('ChallengeName', $result)
            && $result['ChallengeName'] === 'NEW_PASSWORD_REQUIRED'
            && array_key_exists('ChallengeParameters', $result)) {
            $challengeUserAttributes = json_decode($result['ChallengeParameters']['userAttributes'], true);

            return [
                'challenge' => $result['ChallengeName'],
                'attributes' => $challengeUserAttributes,
                'session' => $result['Session'],
            ];
        }

        if (! array_key_exists('AuthenticationResult', $result)) {
            throw new UnauthorizedException("Unauthorized!");
        }

        $result = $result['AuthenticationResult'];

        return [
            'challenge' => null,
            'access_token' => $result['AccessToken'],
            'expires_in' => $result['ExpiresIn'],
            'refresh_token' => $result['RefreshToken'],
            'id_token' => $result['IdToken'],
        ];
    }

    /**
     * Client authenticate to cognito
     *
     * @param string $email
     * @param string $password
     * @param string|null $clientId
     * @return array
     */
    public function clientAuthenticate($email, $password, $clientId = null)
    {
        $client = $this->createCognitoIdentityProviderClient();
        $defaultClient = CognitoConfig::getProfileConfig();

        $response = $client->initiateAuth([
            'AuthFlow' => 'USER_PASSWORD_AUTH',
            'AuthParameters' => [
                'USERNAME' => $email,
                'PASSWORD' => $password,
            ],
            'ClientId' => $clientId ?: $defaultClient['id'],
        ]);

        if (! isset($response['AuthenticationResult'])) {
            throw new UnauthorizedException("Unauthorized!");
        }

        $result = $response['AuthenticationResult'];

        return [
            'challenge' => null,
            'access_token' => $result['AccessToken'],
            'expires_in' => $result['ExpiresIn'],
            'refresh_token' => $result['RefreshToken'],
            'id_token' => $result['IdToken'],
        ];
    }

    /**
     * Get subable (model) by access token.
     *
     * @param string $accessToken
     * @return \Illuminate\Database\Eloquent\Model|null
     */
    public function findSubable($accessToken)
    {
        $decoded = JwtDecoder::plainDecode($accessToken);
        $clientId = $decoded->client_id;
        $segments = explode('/', $decoded->iss);
        $poolId = end($segments);
        $jwk = Http::get("https://cognito-idp.ap-southeast-1.amazonaws.com/{$poolId}/.well-known/jwks.json")
            ->json();
        $userPool = new UserPool(
            $poolId,
            [$clientId],
            CognitoConfig::get('region'),
            $jwk,
        );
        $verifier = new CognitoClaimVerifier($userPool);
        $decoder = new JwtDecoder($verifier);
        $token = $decoder->decode($accessToken);
        $sub = $token->getSub();
        
        return CognitoUser::where('sub', $sub)->first()?->subable;
    }

    /**
     * Create a new cognito identity provider client
     *
     * @return \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient
     */
    public function createCognitoIdentityProviderClient()
    {
        return new CognitoIdentityProviderClient(CognitoConfig::getCredentials() + [
            'region' => CognitoConfig::get('region'),
            'version' => CognitoConfig::get('version')
        ]);
    }

    /**
     * Get password manager
     *
     * @return \Yomafleet\CognitoAuthenticator\PasswordManager
     */
    public function passwordManager()
    {
        if (! $this->passwordManager) {
            $this->passwordManager = new PasswordManager($this->createCognitoIdentityProviderClient());
        }

        return $this->passwordManager;
    }

    /**
     * Get user manager
     *
     * @return \Yomafleet\CognitoAuthenticator\UserManager
     */
    public function userManager()
    {
        if (! $this->userManager) {
            $this->userManager = new UserManager($this->createCognitoIdentityProviderClient());
        }

        return $this->userManager;
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
