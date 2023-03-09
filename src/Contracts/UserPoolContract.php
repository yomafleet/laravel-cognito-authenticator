<?php

namespace Yomafleet\CognitoAuthenticator\Contracts;

use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;

interface UserPoolContract
{
    /**
     * Get errors associated with a token's claims within the user pool.
     *
     * @param  \Yomafleet\CognitoAuthenticator\Contracts\TokenContract  $token
     * @return string|null
     */
    public function getClaimsError(TokenContract $token);

    /**
     * Check if a token has valid claims within the user pool.
     *
     * @param  \Yomafleet\CognitoAuthenticator\Contracts\TokenContract  $token
     * @return bool
     */
    public function hasValidClaims(TokenContract $token);

    /**
     * @return string
     */
    public function getId();

    /**
     * @return string[]
     */
    public function getClientIds();

    /**
     * @return string
     */
    public function getRegion();

    /**
     * @return array
     */
    public function getJwk();
}
