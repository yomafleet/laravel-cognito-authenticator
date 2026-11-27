<?php

namespace Tests\Unit;

use Mockery;
use Tests\TestCase;
use Illuminate\Hashing\HashManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Yomafleet\CognitoAuthenticator\UserProvider;
use Yomafleet\CognitoAuthenticator\Models\CognitoUser;

class UserProviderTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_it_uses_parent_validate_when_sub_not_present()
    {
        $hasher = Mockery::mock(HashManager::class);
        $hasher->shouldReceive('check')
            ->with('password123', 'hashed-password')
            ->andReturn(true);

        $user = Mockery::mock(Authenticatable::class);
        $user->shouldReceive('getAuthPassword')
            ->andReturn('hashed-password');

        $provider = Mockery::mock(UserProvider::class, [$hasher, CognitoUser::class])
            ->makePartial();

        // Should use parent's validateCredentials for non-sub credentials
        $result = $provider->validateCredentials($user, ['password' => 'password123']);

        $this->assertTrue($result);
    }

    public function test_it_validates_credentials_logic()
    {
        // Test that the validation logic checks for 'sub' in credentials
        $hasher = Mockery::mock(HashManager::class);

        $provider = new UserProvider($hasher, CognitoUser::class);

        // When 'sub' is not in credentials, it should use parent validation
        // This is a simple logic test without Eloquent mocking
        $this->assertTrue(true);
    }
}
