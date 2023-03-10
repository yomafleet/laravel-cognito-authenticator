<?php

namespace Tests\Factories;

use Tests\TestCase;
use Illuminate\Support\Str;
use Yomafleet\CognitoAuthenticator\Factories\TokenFactory;

class TokenFactoryTest extends TestCase
{
    /** @dataProvider token_use_provider */
    public function test_token_factory_create_token(array $claims)
    {
        $factory = new TokenFactory();
        $token = $factory->create($claims);
        $name = Str::studly($claims['token_use'].'_token');
        $reflection = new \ReflectionClass($token);

        $this->assertEquals($name, $reflection->getShortName());
    }

    /** @return string[] */
    public function token_use_provider()
    {
        $region = env('AWS_REGION');
        $poolId = env('AWS_COGNITO_USER_POOL_ID');
        $sub = 'abcd';
        $iss = "https://cognito-idp.{$region}.amazonaws.com/{$poolId}";

        return [
            [['token_use' => 'id', 'sub' => $sub, 'iss' => $iss, 'aud' => '']],
            [['token_use' => 'access', 'sub' => $sub, 'iss' => $iss, 'aud' => null]],
        ];
    }
}
