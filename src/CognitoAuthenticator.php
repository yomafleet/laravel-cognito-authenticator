<?php

namespace Yomafleet\CognitoAuthenticator;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Yomafleet\CognitoAuthenticator\Contracts\AuthenticableContract;

class CognitoAuthenticator implements AuthenticableContract
{
    /** @var \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient */
    protected $client;

    /** @var string */
    protected $clientId;

    /** @var string */
    protected $poolId;

    /** @var string */
    protected $clientSecret;

    public function __construct(
        CognitoIdentityProviderClient $client,
        $poolId,
        $clientId,
        $clientSecret,
    ) {
        $this->client = $client;
        $this->clientId = $clientId;
        $this->poolId = $poolId;
        $this->clientSecret = $clientSecret;
    }

    /**
     * Authenticate a user via cognito
     *
     * @param string $identifier
     * @param string $password
     * @return \Aws\Result
     */
    public function authenticate($identifier, $password)
    {
        return $this->client->adminInitiateAuth([
            'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
            'AuthParameters' => [
                'USERNAME' => $identifier,
                'PASSWORD' => $password,
                'SECRET_HASH' => $this->cognitoSecretHash($identifier),
            ],
            'ClientId' => $this->clientId,
            'UserPoolId' => $this->poolId,
        ]);
    }

    /**
     * Creates the Cognito secret hash.
     *
     * @param  string  $username
     * @return string
     */
    protected function cognitoSecretHash($username)
    {
        return $this->hash($username.$this->clientId);
    }

    /**
     * Creates a HMAC from a string.
     *
     * @param  string  $message
     * @return string
     */
    protected function hash($message)
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            $this->clientSecret,
            true
        );

        return base64_encode($hash);
    }
}
