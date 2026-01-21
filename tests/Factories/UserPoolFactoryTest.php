<?php

namespace Tests\Factories;

use Yomafleet\CognitoAuthenticator\Factories\UserPoolFactory;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;
use Mockery;

class UserPoolFactoryTest extends TestCase
{
    public function test_can_get_jwk()
    {
        $poolId =  env('AWS_COGNITO_USER_POOL_ID');

        // mock config
        config([
            'cognito.client_profiles.main' => $poolId,
            'region' => env('AWS_REGION'),
        ]);

        // mock jwk result
        $fakeJwk = ['kid' => 'asdfasdf'];
        $jwkUrl = "https://cognito-idp.ap-southeast-1.amazonaws.com/{$poolId}/.well-known/jwks.json";
        Http::fake([$jwkUrl => Http::response($fakeJwk)]);

        // mock cache
        Cache::shouldReceive('get')
            ->once()
            ->with($poolId, Mockery::on(fn($c) => is_callable($c)))
            ->andReturn($fakeJwk);

        $factory = new UserPoolFactory();
        $jwk = $factory->getJwk();

        $this->assertEqualsCanonicalizing($jwk, $fakeJwk);
    }
}
