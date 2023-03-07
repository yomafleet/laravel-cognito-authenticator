<?php

namespace Yomafleet\CognitoAuthenticator\Models\Token;

use Yomafleet\CognitoAuthenticator\Models\Token;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract;

class IdToken extends Token
{
    public function getClaimsError(UserPoolContract $userPool)
    {
        if (array_search($this->getClaim('aud'), $userPool->getClientIds()) === false) {
            return 'Invalid aud claim';
        }

        $url = "https://cognito-idp.{$userPool->getRegion()}.amazonaws.com/{$userPool->getId()}";

        if ($this->getClaim('iss') !== $url) {
            return 'Invalid iss claim';
        }

        if ($this->getClaim('token_use') !== 'id') {
            return 'Invalid token_use claim';
        }

        return null;
    }
}
