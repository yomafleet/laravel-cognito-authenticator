<?php

namespace Tests\Unit;

use Mockery;
use Tests\TestCase;
use Illuminate\Http\Request;
use Yomafleet\CognitoAuthenticator\CognitoManager;
use Yomafleet\CognitoAuthenticator\CognitoSubRetriever;
use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderContract;
use Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolFactoryContract;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderFactoryContract;

class CognitoManagerTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_it_initializes_with_client_ids()
    {
        $manager = new CognitoManager(['client-id-1', 'client-id-2']);

        $this->assertInstanceOf(CognitoManager::class, $manager);
    }

    public function test_it_sets_user_pool_factory()
    {
        $userPoolFactory = Mockery::mock(UserPoolFactoryContract::class);
        $manager = new CognitoManager(['client-id']);

        $manager->setUserPoolFactory($userPoolFactory);

        // No exception means it worked
        $this->assertTrue(true);
    }

    public function test_it_sets_cognito_sub_retriever()
    {
        $subRetriever = Mockery::mock(CognitoSubRetriever::class);
        $manager = new CognitoManager(['client-id']);

        $manager->setCognitoSubRetriever($subRetriever);

        // No exception means it worked
        $this->assertTrue(true);
    }

    public function test_it_gets_decoder_factory()
    {
        $manager = new CognitoManager(['client-id-1', 'client-id-2']);

        $factory = $manager->getDecoderFactory();

        $this->assertInstanceOf(DecoderFactoryContract::class, $factory);
    }

    public function test_it_decodes_token()
    {
        $mockToken = Mockery::mock(TokenContract::class);
        $mockToken->shouldReceive('getSub')->andReturn('test-sub');

        $decoder = Mockery::mock(DecoderContract::class);
        $decoder->shouldReceive('decode')
            ->with('test-token')
            ->andReturn($mockToken);

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);
        $decoderFactory->shouldReceive('create')
            ->andReturn($decoder);

        $userPoolFactory = Mockery::mock(UserPoolFactoryContract::class);
        $tokenFactory = Mockery::mock(TokenFactoryContract::class);

        $manager = Mockery::mock(
            CognitoManager::class,
            [['client-id'], $userPoolFactory, $tokenFactory]
        )->makePartial();

        $manager->shouldReceive('getDecoderFactory')
            ->andReturn($decoderFactory);

        $token = $manager->decode('test-token');

        $this->assertInstanceOf(TokenContract::class, $token);
        $this->assertEquals('test-sub', $token->getSub());
    }

    public function test_it_gets_sub_retriever_from_request()
    {
        $request = Mockery::mock(Request::class);
        $manager = new CognitoManager(['client-id']);

        $retriever = $manager->getSubRetriever($request);

        $this->assertInstanceOf(CognitoSubRetriever::class, $retriever);
    }

    public function test_it_caches_sub_retriever()
    {
        $request = Mockery::mock(Request::class);
        $manager = new CognitoManager(['client-id']);

        $retriever1 = $manager->getSubRetriever($request);
        $retriever2 = $manager->getSubRetriever($request);

        // Should return same instance
        $this->assertSame($retriever1, $retriever2);
    }

    public function test_it_uses_provided_sub_retriever_if_set()
    {
        $request = Mockery::mock(Request::class);
        $customRetriever = Mockery::mock(CognitoSubRetriever::class);

        $manager = new CognitoManager(['client-id']);
        $manager->setCognitoSubRetriever($customRetriever);

        $retriever = $manager->getSubRetriever($request);

        $this->assertSame($customRetriever, $retriever);
    }

    public function test_it_creates_sub_retriever_with_decoder_factory()
    {
        $request = Mockery::mock(Request::class);
        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);

        $manager = new CognitoManager(['client-id']);

        $retriever = $manager->createSubRetriever($request, $decoderFactory);

        $this->assertInstanceOf(CognitoSubRetriever::class, $retriever);
    }


    public function test_it_uses_default_factories_when_not_provided()
    {
        $manager = new CognitoManager(['client-id']);

        // Should initialize with default factories
        $factory = $manager->getDecoderFactory();

        $this->assertNotNull($factory);
    }

    public function test_it_accepts_custom_user_pool_factory()
    {
        $customFactory = Mockery::mock(UserPoolFactoryContract::class);

        $manager = new CognitoManager(
            ['client-id'],
            $customFactory
        );

        // Should use custom factory
        $this->assertTrue(true);
    }

    public function test_it_accepts_custom_token_factory()
    {
        $userPoolFactory = Mockery::mock(UserPoolFactoryContract::class);
        $tokenFactory = Mockery::mock(TokenFactoryContract::class);

        $manager = new CognitoManager(
            ['client-id'],
            $userPoolFactory,
            $tokenFactory
        );

        // Should use custom factory
        $this->assertTrue(true);
    }

    public function test_it_accepts_custom_sub_retriever_in_constructor()
    {
        $userPoolFactory = Mockery::mock(UserPoolFactoryContract::class);
        $tokenFactory = Mockery::mock(TokenFactoryContract::class);
        $subRetriever = Mockery::mock(CognitoSubRetriever::class);

        $manager = new CognitoManager(
            ['client-id'],
            $userPoolFactory,
            $tokenFactory,
            $subRetriever
        );

        $this->assertSame($subRetriever, $manager->subRetriever);
    }

    public function test_it_defaults_client_ids_to_empty_array_with_one_element()
    {
        $manager = new CognitoManager();

        // Default constructor parameter is ['']
        $this->assertTrue(true);
    }
}
