<?php

namespace Yomafleet\CognitoAuthenticator\Models;

use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract;

class UserPool implements UserPoolContract
{
    /**
     * @var string
     */
    protected $id;

    /**
     * @var string[]
     */
    protected $clientIds;

    /**
     * @var string
     */
    protected $region;

    /**
     * @var array
     */
    protected $jwk;

    /**
     * UserPool constructor.
     *
     * @param  string  $id
     * @param  string[]  $clientIds
     * @param  string  $region
     * @param  array  $jwk  - a json decoded JSON Web Key for the pool
     */
    public function __construct(
        $id,
        $clientIds,
        $region,
        array $jwk
    ) {
        $this->id = $id;
        $this->clientIds = $clientIds;
        $this->region = $region;
        $this->jwk = $jwk;
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @return string[]
     */
    public function getClientIds()
    {
        return $this->clientIds;
    }

    /**
     * @return string
     */
    public function getRegion()
    {
        return $this->region;
    }

    /**
     * @return array
     */
    public function getJwk()
    {
        return $this->jwk;
    }

    /**
     * Get errors associated with a token's claims within the user pool.
     *
     * @param  \Yomafleet\CognitoAuthenticator\Contracts\TokenContract  $token
     * @return string|null
     */
    public function getClaimsError(TokenContract $token)
    {
        return $token->getClaimsError($this);
    }

    /**
     * Check if a token has valid claims within the user pool.
     *
     * @param  \Yomafleet\CognitoAuthenticator\Contracts\TokenContract  $token
     * @return bool
     */
    public function hasValidClaims(TokenContract $token)
    {
        return is_null($this->getClaimsError($token));
    }
}
