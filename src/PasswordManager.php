<?php

namespace Yomafleet\CognitoAuthenticator;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;

class PasswordManager
{
    /** @var \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient */
    protected $client;

    /** @var array */
    protected $config;

    public function __construct(CognitoIdentityProviderClient $client)
    {
        $this->client = $client;
        $this->config = config('cognito');
    }

    /**
     * Request a forgot password to cognito
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function forgotPassword(string $email)
    {
        $this->client->forgotPassword([
            'Username' => $email,
            'ClientId' => $this->config['id'],
            'SecretHash' => $this->secretHash($email),
        ]);
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
        return $this->client->confirmForgotPassword([
            'ConfirmationCode' => $code,
            'Username' => $email,
            'Password' => $password,
            'ClientId' => $this->config['id'],
            'SecretHash' => $this->secretHash($email),
        ]);
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
     * @param string $token
     * @return array
     */
    public function adminRefreshToken($token)
    {
        $response = $this->client->adminInitiateAuth([
            'AuthFlow' => 'REFRESH_TOKEN_AUTH',
            'AuthParameters' => [
                'REFRESH_TOKEN' => $token,
                'SECRET_HASH' => $this->secretHash($token),
            ],
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
        ];
    }

    /**
     * Refresh tokens for current user
     *
     * @param string $token
     * @return array
     */
    public function refreshToken($token)
    {
        $response = $this->client->initiateAuth([
            'AuthFlow' => 'REFRESH_TOKEN_AUTH',
            'AuthParameters' => [
                'REFRESH_TOKEN' => $token,
            ],
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
}
