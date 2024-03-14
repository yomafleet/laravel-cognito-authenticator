<?php

namespace Yomafleet\CognitoAuthenticator;

use Illuminate\Support\Arr;
use Yomafleet\CognitoAuthenticator\CognitoConfig;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Yomafleet\CognitoAuthenticator\Exceptions\InvalidStructureException;

class UserManager
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
     * Create a new user in cognito.
     *
     * @param array $attributes
     * @param boolean $surpress
     * @param boolean $resend
     * @param boolean $verified
     * @return \Aws\Result
     */
    public function adminCreateUser($attributes, $surpress = true, $resend = false, $verfied = false)
    {
        $required = ['name', 'email', 'password'];

        foreach ($required as $key) {
            if (! isset($attributes[$key])) {
                throw new InvalidStructureException(
                    "Required parameter named '{$key}' is not found."
                );
            }
        }

        $createUserAttributes = Arr::only($attributes, ['name', 'email']);
        $createUserAttributes['email_verified'] = $verfied ? 'true' : 'false';

        $map = [];

        foreach ($createUserAttributes as $key => $value) {
            $map[] = ['Name' => $key, 'Value' => $value];
        }

        $createUser = [
            'UserAttributes' => $map,
            'Username' => $attributes['email'],
            'UserPoolId' => $this->config['pool_id'],
        ];

        if ($surpress) {
            $createUser['MessageAction'] = 'SUPPRESS';
        } else {
            $createUser['TemporaryPassword'] = $attributes['password'];
            $createUser['DesiredDeliveryMediums'] = ['EMAIL'];
            if ($resend) {
                $createUser['MessageAction'] = 'RESEND';
            }
        }

        $result = $this->client->adminCreateUser($createUser);

        if ($surpress) {
            $this->client->adminSetUserPassword([
                'Password' => $attributes['password'],
                'Permanent' => true,
                'Username' => $result['User']['Username'],
                'UserPoolId' => $this->config['pool_id'],
            ]);
        }

        return $result;
    }

    /**
     * Update user attributes as admin
     *
     * @param string $email
     * @param array $attributes
     * @param boolean $verified
     * @return \Aws\Result
     */
    public function adminUpdateUserAttributes(string $email, array $attributes, $verfied = false)
    {
        $map = [];

        foreach ($attributes as $name => $value) {
            if ($name === 'phone') {
                $map[] = ['Name' => 'phone_number', 'Value' => $value];
                $map[] = ['Name' => 'phone_number_verified', 'Value' => $verfied ? "true" : "false"];
            } elseif ($name === 'fullname') {
                $map[] = ['Name' => 'name', 'Value' => $value];
            } else {
                $map[] = ['Name' => $name, 'Value' => $value];
                if ($name === 'email') {
                    $map[] = ['Name' => 'email_verified', 'Value' => $verfied ? "true" : "false"];
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
     * Verify user
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminVerifyUser(string $email)
    {
        $this->adminUpdateUserAttributes($email, [
            'email' => $email,
        ], true);

        return $this->client->adminConfirmSignUp([
            'UserPoolId' => $this->config['pool_id'],
            'Username' => $email,
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
