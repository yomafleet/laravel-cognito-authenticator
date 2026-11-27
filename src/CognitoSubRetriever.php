<?php

namespace Yomafleet\CognitoAuthenticator;

use Illuminate\Http\Request;
use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;
use Yomafleet\CognitoAuthenticator\Actions\DecodeTokenAction;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderContract;
use Yomafleet\CognitoAuthenticator\Exceptions\TokenException;
use Yomafleet\CognitoAuthenticator\Contracts\CanGetSubContract;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderFactoryContract;
use Yomafleet\CognitoAuthenticator\Exceptions\IdTokenHeaderNotFoundException;
use Yomafleet\CognitoAuthenticator\Exceptions\AuthorizationHeaderNotFoudException;

class CognitoSubRetriever implements CanGetSubContract
{
    /** @var \Illuminate\Http\Request */
    protected $request;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\DecoderFactoryContract */
    protected $decoderFactory;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\DecoderContract */
    protected $decoder;

    public function __construct(Request $request, DecoderFactoryContract $decoderFactory)
    {
        $this->request = $request;
        $this->decoderFactory = $decoderFactory;
    }

    /**
     * Get JWT decoder.
     *
     * @return \Yomafleet\CognitoAuthenticator\Contracts\DecoderContract
     */
    public function getDecoder(): DecoderContract
    {
        if ($this->decoder) {
            return $this->decoder;
        }

        $this->decoder = $this->decoderFactory->create();

        return $this->decoder;
    }

    /**
     * Get "sub" of token from request header.
     *
     * @param string $tokenType either 'access' or 'id'
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException
     * @return string
     */
    public function getSub($tokenType = 'access')
    {
        $token = $this->getDecoded($tokenType);

        return $token->getSub();
    }

    /**
     * Get the token.
     *
     * @param string $tokenType either 'access' or 'id'
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException
     * @return \Yomafleet\CognitoAuthenticator\Contracts\TokenContract
     */
    public function getDecoded($tokenType = 'access'): TokenContract
    {
        if (! in_array($tokenType, ['access', 'id'])) {
            throw new TokenException(
                'Only "access" or "id" token type is support to fetch "sub".'
            );
        }

        $name = 'get'.ucfirst($tokenType).'TokenHeader';
        $decodeToken = new DecodeTokenAction($this->$name(), $this->getDecoder());
        return $decodeToken();
    }

    /**
     * Retrieve 'Authorization' header from request header.
     *
     * @return string
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\AuthorizationHeaderNotFoudException
     */
    public function getAccessTokenHeader()
    {
        $authorization = $this->request->header('authorization');

        if (! $authorization) {
            throw new AuthorizationHeaderNotFoudException();
        }

        return $authorization;
    }

    /**
     * Retrieve id_token header from request header.
     *
     * @return string
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\IdTokenHeaderNotFoundException
     */
    public function getIdTokenHeader()
    {
        $headerName = CognitoConfig::get('id_token_name');
        $idToken = $this->request->header($headerName);

        if (! $idToken) {
            throw new IdTokenHeaderNotFoundException("ID token header not found!");
        }

        return $idToken;
    }
}
