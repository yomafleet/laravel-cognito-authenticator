<?php

namespace Yomafleet\CognitoAuthenticator\Actions;

use Illuminate\Validation\UnauthorizedException;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderContract;
use Yomafleet\CognitoAuthenticator\Contracts\CanGetSubContract;

class GetSubAction implements CanGetSubContract
{
    /** @var string */
    protected $token;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\DecoderContract $decoder */
    protected $decoder;

    public function __construct(
        string $token,
        DecoderContract $decoder,
    ) {
        $this->token = $this->parseBearer($token);
        $this->decoder = $decoder;
    }

    /**
     * Get "sub" from the token.
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException
     * @return string
     */
    public function __invoke(): string
    {
        return $this->getSub();
    }

    /**
     * Get "sub" from the token.
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException
     * @return string
     */
    public function getSub(): string
    {
        $token = $this->decoder->decode($this->token);

        if (! $token) {
            throw new UnauthorizedException();
        }

        return $token->getSub();
    }

    /**
     * Remove 'Bearer ' prefix from bearer token.
     *
     * @return string
     */
    protected function parseBearer(string $bearer)
    {
        return trim(str_ireplace('Bearer ', '', $bearer));
    }
}
