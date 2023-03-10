<?php

namespace Yomafleet\CognitoAuthenticator\Factories;

use Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract;
use Yomafleet\CognitoAuthenticator\Exceptions\InvalidClaimsException;
use Yomafleet\CognitoAuthenticator\Models\Token\AccessToken;
use Yomafleet\CognitoAuthenticator\Models\Token\IdToken;
use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;
use Yomafleet\CognitoAuthenticator\Traits\ValidatesClaims;

class TokenFactory implements TokenFactoryContract
{
    use ValidatesClaims;

    /**
     * {@inheritDoc}
     *
     * @param  array  $claims
     * @param  array  $requiredClaims
     * @return \Yomafleet\CognitoAuthenticator\Contracts\TokenContract
     */
    public function create(array $claims, array $requiredClaims = []): TokenContract
    {
        $claims = $this->prepareClaims($claims, $requiredClaims);

        $tokenUse = $claims['token_use'];

        switch ($tokenUse) {
            case 'id':
                return new IdToken($claims);
            case 'access':
                return new AccessToken($claims);
            default:
                throw new InvalidClaimsException('Invalid token_use claim');
        }
    }

    /**
     * Validate claims and check 'token_use' field.
     *
     * @param array $claims
     * @param array $requiredClaims
     * @return array
     */
    public function prepareClaims(array $claims, array $requiredClaims): array
    {
        $this->validateClaims($claims, $requiredClaims);

        if (! isset($claims['token_use'])) {
            throw new InvalidClaimsException('Missing token_use claim');
        }

        return $claims;
    }
}
