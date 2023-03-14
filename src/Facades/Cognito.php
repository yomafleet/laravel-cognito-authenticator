<?php

namespace Yomafleet\CognitoAuthenticator\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static array createVerifier(array $clientIds)
 * @method array authenticate($identifier, $password)
 * @method static \Yomafleet\CognitoAuthenticator\JwtDecoder createJwtDecoder()
 * @method static \Yomafleet\CognitoAuthenticator\CognitoSubRetriever getSubRetriever(\Illuminate\Http\Request $request, \Yomafleet\CognitoAuthenticator\Contracts\DecoderContract|null $decoder)
 *
 * @see \Yomafleet\CognitoAuthenticator\CognitoManager
 */
class Cognito extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'cognito-authenticator';
    }
}
