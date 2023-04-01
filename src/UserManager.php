<?php

namespace Yomafleet\CognitoAuthenticator;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;

class UserManager
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
     * Update user attributes as admin
     *
     * @param string $email
     * @param array $attributes
     * @return \Aws\Result
     */
    public function adminUpdateUserAttributes(string $email, array $attributes)
    {
        $map = [];

        foreach ($attributes as $name => $value) {
            if ($name === 'phone') {
                $map[] = ['Name' => 'phone_number', 'Value' => $value];
                $map[] = ['Name' => 'phone_number_verified', 'Value' => "true"];
            } else {
                $map[] = ['Name' => $name, 'Value' => $value];
                if ($name === 'email') {
                    $map[] = ['Name' => 'email_verified', 'Value' => "true"];
                }
            }
        }

        return $this->client->adminUpdateUserAttributes([
            'Username' => $email,
            'UserAttributes' => $map,
            'UserPoolId' => $this->config['pool_id'],
        ]);
    }

    /**
     * Disable user as admin
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminDisableUser(string $email)
    {
        return $this->client->adminDisableUser([
            'Username' => $email,
            'UserPoolId' => $this->config['pool_id'],
        ]);
    }

    /**
     * Enable user as admin
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminEnableUser(string $email)
    {
        return $this->client->adminEnableUser([
            'Username' => $email,
            'UserPoolId' => $this->config['pool_id'],
        ]);
    }

    /**
     * Get user as admin
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminGetUser(string $email)
    {
        return $this->client->adminGetUser([
            'Username' => $email,
            'UserPoolId' => $this->config['pool_id'],
        ]);
    }

    /**
     * Sign-out user globally as admin
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminUserGlobalSignOut(string $email)
    {
        return $this->client->adminUserGlobalSignOut([
            'Username' => $email,
            'UserPoolId' => $this->config['pool_id'],
        ]);
    }

    /**
     * Delete user as admin
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminDeleteUser(string $email)
    {
        return $this->client->adminDeleteUser([
            'Username' => $email,
            'UserPoolId' => $this->config['pool_id'],
        ]);
    }

    /**
     * Delete user attributes as admin
     *
     * @param string $email
     * @param array $attributes
     * @return \Aws\Result
     */
    public function adminDeleteUserAttributes(string $email, array $attributes)
    {
        return $this->client->adminDeleteUserAttributes([
            'Username' => $email,
            'UserAttributeNames' => $attributes,
            'UserPoolId' => $this->config['pool_id'],
        ]);
    }
}
