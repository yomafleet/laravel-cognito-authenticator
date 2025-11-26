<?php

namespace Tests\Unit;

use Mockery;
use Tests\TestCase;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Yomafleet\CognitoAuthenticator\CognitoGuard;
use Yomafleet\CognitoAuthenticator\Contracts\CanGetSubContract;

class CognitoGuardTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_it_returns_null_user_when_sub_cannot_be_retrieved()
    {
        $provider = Mockery::mock(UserProvider::class);

        $subRetriever = Mockery::mock(CanGetSubContract::class);
        $subRetriever->shouldReceive('getSub')
            ->andThrow(new \Exception('Token not found'));

        $guard = new CognitoGuard($provider, $subRetriever);

        $this->assertNull($guard->user());
    }

    public function test_it_returns_null_user_when_sub_is_null()
    {
        $provider = Mockery::mock(UserProvider::class);

        $subRetriever = Mockery::mock(CanGetSubContract::class);
        $subRetriever->shouldReceive('getSub')
            ->andReturn(null);

        $guard = new CognitoGuard($provider, $subRetriever);

        $this->assertNull($guard->user());
    }

    public function test_it_retrieves_user_by_sub_from_provider()
    {
        $mockUser = Mockery::mock(Authenticatable::class);

        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')
            ->with(['sub' => 'test-sub-123'])
            ->andReturn($mockUser);

        $subRetriever = Mockery::mock(CanGetSubContract::class);
        $subRetriever->shouldReceive('getSub')
            ->andReturn('test-sub-123');

        $guard = new CognitoGuard($provider, $subRetriever);

        $user = $guard->user();

        $this->assertSame($mockUser, $user);
    }

    public function test_it_returns_null_when_user_not_found_in_database()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')
            ->with(['sub' => 'non-existent-sub'])
            ->andReturn(null);

        $subRetriever = Mockery::mock(CanGetSubContract::class);
        $subRetriever->shouldReceive('getSub')
            ->andReturn('non-existent-sub');

        $guard = new CognitoGuard($provider, $subRetriever);

        $this->assertNull($guard->user());
    }

    public function test_it_caches_user_after_first_retrieval()
    {
        $mockUser = Mockery::mock(Authenticatable::class);

        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')
            ->once() // Should only be called once
            ->with(['sub' => 'test-sub'])
            ->andReturn($mockUser);

        $subRetriever = Mockery::mock(CanGetSubContract::class);
        $subRetriever->shouldReceive('getSub')
            ->once() // Should only be called once
            ->andReturn('test-sub');

        $guard = new CognitoGuard($provider, $subRetriever);

        // Call user() twice
        $user1 = $guard->user();
        $user2 = $guard->user();

        // Should return same instance both times
        $this->assertSame($user1, $user2);
        $this->assertSame($mockUser, $user1);
    }

    public function test_it_validates_credentials_with_sub()
    {
        $mockUser = Mockery::mock(Authenticatable::class);

        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')
            ->with(['sub' => 'valid-sub'])
            ->andReturn($mockUser);

        $subRetriever = Mockery::mock(CanGetSubContract::class);

        $guard = new CognitoGuard($provider, $subRetriever);

        $result = $guard->validate(['sub' => 'valid-sub']);

        $this->assertTrue($result);
    }

    public function test_it_returns_false_when_validating_empty_credentials()
    {
        $provider = Mockery::mock(UserProvider::class);
        $subRetriever = Mockery::mock(CanGetSubContract::class);

        $guard = new CognitoGuard($provider, $subRetriever);

        $result = $guard->validate([]);

        $this->assertFalse($result);
    }

    public function test_it_returns_false_when_validating_credentials_without_sub()
    {
        $provider = Mockery::mock(UserProvider::class);
        $subRetriever = Mockery::mock(CanGetSubContract::class);

        $guard = new CognitoGuard($provider, $subRetriever);

        $result = $guard->validate(['email' => 'test@example.com']);

        $this->assertFalse($result);
    }

    public function test_it_returns_false_when_user_not_found_during_validation()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')
            ->with(['sub' => 'non-existent'])
            ->andReturn(null);

        $subRetriever = Mockery::mock(CanGetSubContract::class);

        $guard = new CognitoGuard($provider, $subRetriever);

        $result = $guard->validate(['sub' => 'non-existent']);

        $this->assertFalse($result);
    }

    public function test_it_uses_sub_as_identifier_name()
    {
        $this->assertEquals('sub', CognitoGuard::IDENTIFIER_NAME);
    }

    public function test_it_handles_throwable_exceptions_gracefully()
    {
        $provider = Mockery::mock(UserProvider::class);

        $subRetriever = Mockery::mock(CanGetSubContract::class);
        $subRetriever->shouldReceive('getSub')
            ->andThrow(new \RuntimeException('Something went wrong'));

        $guard = new CognitoGuard($provider, $subRetriever);

        // Should not throw exception, should return null instead
        $user = $guard->user();

        $this->assertNull($user);
    }

    public function test_it_only_retrieves_sub_once_when_cached()
    {
        $mockUser = Mockery::mock(Authenticatable::class);

        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($mockUser);

        $subRetriever = Mockery::mock(CanGetSubContract::class);
        $subRetriever->shouldReceive('getSub')
            ->once()  // Should only call once
            ->andReturn('cached-sub');

        $guard = new CognitoGuard($provider, $subRetriever);

        // Multiple calls to user()
        $guard->user();
        $guard->user();
        $guard->user();

        // Mockery will verify getSub() was only called once
        $this->assertTrue(true);
    }

    public function test_it_filters_credentials_to_only_sub_during_validation()
    {
        $mockUser = Mockery::mock(Authenticatable::class);

        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')
            ->with(['sub' => 'test-sub']) // Should only pass 'sub', not other fields
            ->andReturn($mockUser);

        $subRetriever = Mockery::mock(CanGetSubContract::class);

        $guard = new CognitoGuard($provider, $subRetriever);

        // Pass multiple credentials
        $result = $guard->validate([
            'sub' => 'test-sub',
            'email' => 'test@example.com',
            'name' => 'Test User'
        ]);

        $this->assertTrue($result);
    }
}
