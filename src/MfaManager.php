<?php

namespace Yomafleet\CognitoAuthenticator;

use Yomafleet\CognitoAuthenticator\CognitoConfig;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;

class MfaManager
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
     * Begin software token (TOTP) enrollment and get back a secret code to
     * render as a QR code. Pass an access token for a user enrolling after
     * a normal login, or a challenge session if Cognito issued an MFA_SETUP
     * challenge directly during authentication.
     *
     * @param string|null $accessToken
     * @param string|null $session
     * @return array
     */
    public function associateSoftwareToken($accessToken = null, $session = null)
    {
        $response = $this->client->associateSoftwareToken(
            $this->tokenOrSessionParams($accessToken, $session)
        );

        return [
            'secret_code' => $response['SecretCode'],
            'session' => $response['Session'] ?? null,
        ];
    }

    /**
     * Verify a software token (TOTP) code to complete enrollment. Pass the
     * same token type (access token or session) used to associate it.
     *
     * @param string $userCode
     * @param string|null $accessToken
     * @param string|null $session
     * @param string|null $friendlyDeviceName
     * @return array
     */
    public function verifySoftwareToken($userCode, $accessToken = null, $session = null, $friendlyDeviceName = null)
    {
        $params = $this->tokenOrSessionParams($accessToken, $session) + [
            'UserCode' => $userCode,
        ];

        if ($friendlyDeviceName) {
            $params['FriendlyDeviceName'] = $friendlyDeviceName;
        }

        $response = $this->client->verifySoftwareToken($params);

        return [
            'status' => $response['Status'],
            'session' => $response['Session'] ?? null,
        ];
    }

    /**
     * Respond to a SOFTWARE_TOKEN_MFA challenge during login.
     *
     * @param string $email
     * @param string $session
     * @param string $code
     * @return array
     */
    public function respondToMfaChallenge($email, $session, $code)
    {
        $response = $this->client->respondToAuthChallenge([
            'ChallengeName' => 'SOFTWARE_TOKEN_MFA',
            'ClientId' => $this->config['id'],
            'Session' => $session,
            'ChallengeResponses' => [
                'SOFTWARE_TOKEN_MFA_CODE' => $code,
                'USERNAME' => $email,
                'SECRET_HASH' => $this->secretHash($email),
            ],
        ]);

        $result = $response['AuthenticationResult'] ?? null;

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
     * Require software token MFA for a user going forward.
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminRequireSoftwareTokenMfa(string $email)
    {
        return $this->client->adminSetUserMFAPreference([
            'SoftwareTokenMfaSettings' => [
                'Enabled' => true,
                'PreferredMfa' => true,
            ],
            'Username' => $email,
            'UserPoolId' => $this->config['pool_id'],
        ]);
    }

    /**
     * Clear a user's software token MFA requirement, e.g. after losing
     * their authenticator device. They re-enroll on next login.
     *
     * @param string $email
     * @return \Aws\Result
     */
    public function adminClearSoftwareTokenMfa(string $email)
    {
        return $this->client->adminSetUserMFAPreference([
            'SoftwareTokenMfaSettings' => [
                'Enabled' => false,
                'PreferredMfa' => false,
            ],
            'Username' => $email,
            'UserPoolId' => $this->config['pool_id'],
        ]);
    }

    /**
     * Build the mutually-exclusive AccessToken/Session param for whichever
     * one was given.
     *
     * @param string|null $accessToken
     * @param string|null $session
     * @return array
     */
    protected function tokenOrSessionParams($accessToken, $session)
    {
        if ($accessToken) {
            return ['AccessToken' => $accessToken];
        }

        if ($session) {
            return ['Session' => $session];
        }

        throw new \InvalidArgumentException('Either an access token or a session must be provided.');
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
