<?php

namespace Tests\Unit;

use Mockery;
use Tests\TestCase;
use Illuminate\Http\Request;
use Yomafleet\CognitoAuthenticator\CognitoSubRetriever;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderContract;
use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderFactoryContract;
use Yomafleet\CognitoAuthenticator\Exceptions\TokenException;
use Yomafleet\CognitoAuthenticator\Exceptions\AuthorizationHeaderNotFoudException;
use Yomafleet\CognitoAuthenticator\Exceptions\IdTokenHeaderNotFoundException;

class CognitoSubRetrieverTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_it_retrieves_sub_from_access_token()
    {
        $request = Mockery::mock(Request::class);
        $request->shouldReceive('header')
            ->with('authorization')
            ->andReturn('Bearer valid-access-token');

        $token = Mockery::mock(TokenContract::class);
        $token->shouldReceive('getSub')
            ->andReturn('test-sub-123');

        $decoder = Mockery::mock(DecoderContract::class);

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);
        $decoderFactory->shouldReceive('create')
            ->andReturn($decoder);

        $retriever = Mockery::mock(CognitoSubRetriever::class, [$request, $decoderFactory])
            ->makePartial();
        $retriever->shouldReceive('getDecoded')
            ->with('access')
            ->andReturn($token);

        $sub = $retriever->getSub('access');

        $this->assertEquals('test-sub-123', $sub);
    }

    public function test_it_retrieves_sub_from_id_token()
    {
        config(['cognito.id_token_name' => 'X-ID-Token']);

        $request = Mockery::mock(Request::class);
        $request->shouldReceive('header')
            ->with('X-ID-Token')
            ->andReturn('valid-id-token');

        $token = Mockery::mock(TokenContract::class);
        $token->shouldReceive('getSub')
            ->andReturn('test-sub-456');

        $decoder = Mockery::mock(DecoderContract::class);

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);
        $decoderFactory->shouldReceive('create')
            ->andReturn($decoder);

        $retriever = Mockery::mock(CognitoSubRetriever::class, [$request, $decoderFactory])
            ->makePartial();
        $retriever->shouldReceive('getDecoded')
            ->with('id')
            ->andReturn($token);

        $sub = $retriever->getSub('id');

        $this->assertEquals('test-sub-456', $sub);
    }

    public function test_it_throws_exception_when_authorization_header_missing()
    {
        $this->expectException(AuthorizationHeaderNotFoudException::class);

        $request = Mockery::mock(Request::class);
        $request->shouldReceive('header')
            ->with('authorization')
            ->andReturn(null);

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);

        $retriever = new CognitoSubRetriever($request, $decoderFactory);
        $retriever->getAccessTokenHeader();
    }

    public function test_it_throws_exception_when_id_token_header_missing()
    {
        $this->expectException(IdTokenHeaderNotFoundException::class);

        config(['cognito.id_token_name' => 'X-ID-Token']);

        $request = Mockery::mock(Request::class);
        $request->shouldReceive('header')
            ->with('X-ID-Token')
            ->andReturn(null);

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);

        $retriever = new CognitoSubRetriever($request, $decoderFactory);
        $retriever->getIdTokenHeader();
    }

    public function test_it_throws_exception_for_invalid_token_type()
    {
        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('Only "access" or "id" token type is support');

        $request = Mockery::mock(Request::class);
        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);

        $retriever = new CognitoSubRetriever($request, $decoderFactory);
        $retriever->getSub('invalid-type');
    }

    public function test_it_accepts_access_token_type()
    {
        $request = Mockery::mock(Request::class);
        $request->shouldReceive('header')
            ->with('authorization')
            ->andReturn('Bearer token');

        $token = Mockery::mock(TokenContract::class);
        $token->shouldReceive('getSub')->andReturn('sub');

        $decoder = Mockery::mock(DecoderContract::class);

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);
        $decoderFactory->shouldReceive('create')->andReturn($decoder);

        $retriever = Mockery::mock(CognitoSubRetriever::class, [$request, $decoderFactory])
            ->makePartial();
        $retriever->shouldReceive('getDecoded')
            ->with('access')
            ->andReturn($token);

        // Should not throw exception
        $sub = $retriever->getSub('access');
        $this->assertEquals('sub', $sub);
    }

    public function test_it_accepts_id_token_type()
    {
        config(['cognito.id_token_name' => 'X-ID-Token']);

        $request = Mockery::mock(Request::class);
        $request->shouldReceive('header')
            ->with('X-ID-Token')
            ->andReturn('token');

        $token = Mockery::mock(TokenContract::class);
        $token->shouldReceive('getSub')->andReturn('sub');

        $decoder = Mockery::mock(DecoderContract::class);

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);
        $decoderFactory->shouldReceive('create')->andReturn($decoder);

        $retriever = Mockery::mock(CognitoSubRetriever::class, [$request, $decoderFactory])
            ->makePartial();
        $retriever->shouldReceive('getDecoded')
            ->with('id')
            ->andReturn($token);

        // Should not throw exception
        $sub = $retriever->getSub('id');
        $this->assertEquals('sub', $sub);
    }

    public function test_it_gets_decoder_from_factory()
    {
        $request = Mockery::mock(Request::class);

        $decoder = Mockery::mock(DecoderContract::class);

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);
        $decoderFactory->shouldReceive('create')
            ->once()
            ->andReturn($decoder);

        $retriever = new CognitoSubRetriever($request, $decoderFactory);
        $result = $retriever->getDecoder();

        $this->assertSame($decoder, $result);
    }

    public function test_it_caches_decoder_instance()
    {
        $request = Mockery::mock(Request::class);

        $decoder = Mockery::mock(DecoderContract::class);

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);
        $decoderFactory->shouldReceive('create')
            ->once() // Should only be called once
            ->andReturn($decoder);

        $retriever = new CognitoSubRetriever($request, $decoderFactory);

        // Call getDecoder multiple times
        $decoder1 = $retriever->getDecoder();
        $decoder2 = $retriever->getDecoder();

        $this->assertSame($decoder1, $decoder2);
    }

    public function test_it_returns_authorization_header_value()
    {
        $request = Mockery::mock(Request::class);
        $request->shouldReceive('header')
            ->with('authorization')
            ->andReturn('Bearer test-token-123');

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);

        $retriever = new CognitoSubRetriever($request, $decoderFactory);
        $header = $retriever->getAccessTokenHeader();

        $this->assertEquals('Bearer test-token-123', $header);
    }

    public function test_it_returns_id_token_header_value()
    {
        config(['cognito.id_token_name' => 'X-Custom-ID-Token']);

        $request = Mockery::mock(Request::class);
        $request->shouldReceive('header')
            ->with('X-Custom-ID-Token')
            ->andReturn('test-id-token-456');

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);

        $retriever = new CognitoSubRetriever($request, $decoderFactory);
        $header = $retriever->getIdTokenHeader();

        $this->assertEquals('test-id-token-456', $header);
    }

    public function test_it_uses_configured_id_token_header_name()
    {
        config(['cognito.id_token_name' => 'My-Custom-Header']);

        $request = Mockery::mock(Request::class);
        $request->shouldReceive('header')
            ->with('My-Custom-Header')  // Should use configured name
            ->andReturn('token');

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);

        $retriever = new CognitoSubRetriever($request, $decoderFactory);
        $retriever->getIdTokenHeader();

        // Mockery will verify the correct header name was used
        $this->assertTrue(true);
    }

    public function test_it_defaults_to_access_token_when_no_type_specified()
    {
        $request = Mockery::mock(Request::class);
        $request->shouldReceive('header')
            ->with('authorization')
            ->andReturn('Bearer token');

        $token = Mockery::mock(TokenContract::class);
        $token->shouldReceive('getSub')->andReturn('default-sub');

        $decoder = Mockery::mock(DecoderContract::class);

        $decoderFactory = Mockery::mock(DecoderFactoryContract::class);
        $decoderFactory->shouldReceive('create')->andReturn($decoder);

        $retriever = Mockery::mock(CognitoSubRetriever::class, [$request, $decoderFactory])
            ->makePartial();
        $retriever->shouldReceive('getDecoded')
            ->with('access')  // Should default to 'access'
            ->andReturn($token);

        // Call without specifying type
        $sub = $retriever->getSub();

        $this->assertEquals('default-sub', $sub);
    }
}
