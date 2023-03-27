<?php

namespace Yomafleet\CognitoAuthenticator;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;

class PasswordManager
{
    /** @var \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient */
    protected $client;

    public function __construct(CognitoIdentityProviderClient $client)
    {
        $this->client = $client;
    }

    /**
     * Request a forgot password to cognito
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function forgotPassword(string $email)
    {
        $this->client->forgotPassword(['Username' => $email]);
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
        return $this->client->adminResetUserPassword(['Username' => $email]);
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
        ]);
    }
}
