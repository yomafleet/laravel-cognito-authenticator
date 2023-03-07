<?php

namespace Yomafleet\CognitoAuthenticator\Models\Token;

use Yomafleet\CognitoAuthenticator\Models\Token;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract;

class AccessToken extends Token
{
    public function getClaimsError(UserPoolContract $userPool)
    {
        $url = "https://cognito-idp.{$userPool->getRegion()}.amazonaws.com/{$userPool->getId()}";

        if ($this->getClaim('iss') !== $url) {
            return 'Invalid iss claim';
        }

        if ($this->getClaim('token_use') !== 'access') {
            return 'Invalid token_use claim';
        }

        return null;
    }
}
