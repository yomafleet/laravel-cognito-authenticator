<?php

namespace Yomafleet\CognitoAuthenticator;

use Yomafleet\CognitoAuthenticator\CognitoConfig;
use Yomafleet\CognitoAuthenticator\Facades\Cognito;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;

class PasswordManager
{
    /** @var \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient */
    protected $client;

    /** @var array */
    protected $config;

    public function __construct(CognitoIdentityProviderClient $client, $profile = '')
    {
        $this->client = $client;
        $this->config = CognitoConfig::getProfileConfig($profile);
    }

    /**
     * Request a forgot password to cognito
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function forgotPassword(string $email)
    {
        $this->client->forgotPassword($this->decorateWithSecretHash([
            'Username' => $email,
            'ClientId' => $this->config['id'],
        ], $email));
    }

    /**
     * Confirm the previous forgot password with code
     *
     * @param string $email
     * @param string $password
     * @param string $code
     * @return \Aws\Result
     */
    public function confirmForgotPassword($email, $password, $code)
    {
        return $this->client->confirmForgotPassword($this->decorateWithSecretHash([
            'ConfirmationCode' => $code,
            'Username' => $email,
            'Password' => $password,
            'ClientId' => $this->config['id'],
        ], $email));
    }

    /**
     * Reset user password as an admin
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminResetUserPassword($email)
    {
        return $this->client->adminResetUserPassword([
            'Username' => $email,
            'UserPoolId' => $this->config['pool_id'],
        ]);
    }

    /**
     * Admin set user password
     *
     * @param string $email
     * @param string $password
     * @param boolean $permanant
     * @return \Aws\Result
     */
    public function adminSetUserPassword($email, $password, $permanant = true)
    {
        return $this->client->adminSetUserPassword([
            'Password' => $password,
            'Permanent' => $permanant,
            'Username' => $email,
            'UserPoolId' => $this->config['pool_id'],
        ]);
    }

    /**
     * Refresh tokens for admin
     *
     * @param string $refreshToken
     * @param string $idToken
     * @return array
     */
    public function adminRefreshToken($refreshToken, $idToken)
    {
        $response = $this->client->adminInitiateAuth([
            'AuthFlow' => 'REFRESH_TOKEN_AUTH',
            'AuthParameters' => $this->decorateWithSecretHash([
                'REFRESH_TOKEN' => $refreshToken,
            ], $this->getMailFromIdToken($idToken)),
            'ClientId' => $this->config['id'],
        ]);

        $result = $response['AuthenticationResult'] ?: null;

        if (! $result) {
            return $response->toArray();
        }

        return [
            'access_token' => $result['AccessToken'],
            'expires_in' => $result['ExpiresIn'],
            'refresh_token' => $result['RefreshToken'],
            'id_token' => $result['IdToken'],
        ];
    }

    /**
     * Refresh tokens for current user
     *
     * @param string $refreshToken
     * @param string $idToken
     * @return array
     */
    public function refreshToken($refreshToken, $idToken)
    {
        $response = $this->client->initiateAuth([
            'AuthFlow' => 'REFRESH_TOKEN_AUTH',
            'AuthParameters' => $this->decorateWithSecretHash([
                'REFRESH_TOKEN' => $refreshToken,
            ], $this->getMailFromIdToken($idToken)),
            'ClientId' => $this->config['id'],
        ]);

        $result = $response['AuthenticationResult'] ?: null;

        if (! $result) {
            return $response->toArray();
        }

        return [
            'access_token' => $result['AccessToken'],
            'expires_in' => $result['ExpiresIn'],
            'refresh_token' => $result['RefreshToken'],
            'id_token' => $result['IdToken'],
        ];
    }

    /**
     * Attempt the new password challenge
     *
     * @param array $respond
     * @return array
     */
    public function newPasswordChallenge($respond)
    {
        $response = $this->client->respondToAuthChallenge([
            'ChallengeName' => $respond['challenge'],
            'ClientId' => $this->config['id'],
            'Session' => $respond['session'],
            'ChallengeResponses' => $this->decorateWithSecretHash([
                'NEW_PASSWORD' => $respond['new_password'],
                'USERNAME' => $respond['email'],
            ], $respond['email']),
        ]);

        $result = $response['AuthenticationResult'] ?: null;

        if (! $result) {
            return $response->toArray();
        }

        return [
            'challenge' => null,
            'access_token' => $result['AccessToken'],
            'expires_in' => $result['ExpiresIn'],
            'refresh_token' => $result['RefreshToken'],
            'id_token' => $result['IdToken'],
        ];
    }

    /**
     * Generate a secret hash
     *
     * @param string $name
     * @return string
     */
    protected function secretHash($name)
    {
        $hashable = $name . $this->config['id'];
        $signature = hash_hmac('sha256', $hashable, $this->config['secret'], true);

        return base64_encode($signature);
    }

    /**
     * Get mail from id token
     *
     * @param string $token
     * @return string
     */
    protected function getMailFromIdToken($token)
    {
        return Cognito::decode($token)->getClaim('email');
    }

    /**
     * Add secret hash to payload
     *
     * @param array $params
     * @param string $identifier
     * @return array
     */
    protected function decorateWithSecretHash($params, $identifier)
    {
        if ($this->config['id'] && $this->config['secret']) {
            $params['SECRET_HASH'] = $this->secretHash($identifier);
        }

        return $params;
    }
}
