<?php

namespace Yomafleet\CognitoAuthenticator;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;

class UserManager
{
    /** @var \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient */
    protected $client;

    public function __construct(CognitoIdentityProviderClient $client)
    {
        $this->client = $client;
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
            $map[] = ['Name' => $name, 'Value' => $value];
        }

        return $this->client->adminUpdateUserAttributes([
            'Username' => $email,
            'UserAttributes' => $map,
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
        return $this->client->adminDisableUser(['Username' => $email]);
    }

    /**
     * Enable user as admin
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminEnableUser(string $email)
    {
        return $this->client->adminEnableUser(['Username' => $email]);
    }

    /**
     * Get user as admin
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminGetUser(string $email)
    {
        return $this->client->adminGetUser(['Username' => $email]);
    }

    /**
     * Sign-out user globally as admin
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminUserGlobalSignOut(string $email)
    {
        return $this->client->adminUserGlobalSignOut(['Username' => $email]);
    }

    /**
     * Delete user as admin
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminDeleteUser(string $email)
    {
        return $this->client->adminDeleteUser(['Username' => $email]);
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
        ]);
    }
}
