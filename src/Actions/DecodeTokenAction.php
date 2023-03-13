<?php

namespace Yomafleet\CognitoAuthenticator\Actions;

use Illuminate\Validation\UnauthorizedException;
use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderContract;
use Yomafleet\CognitoAuthenticator\Contracts\DecodeTokenContract;

class DecodeTokenAction implements DecodeTokenContract
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
     * Get the decoded token.
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException
     * @return \Yomafleet\CognitoAuthenticator\Contracts\TokenContract
     */
    public function __invoke(): TokenContract
    {
        return $this->decode();
    }

    /**
     * Decode the given token.
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\UnauthorizedException
     * @return \Yomafleet\CognitoAuthenticator\Contracts\TokenContract
     */
    public function decode(): TokenContract
    {
        $token = $this->decoder->decode($this->token);

        if (! $token) {
            throw new UnauthorizedException();
        }

        return $token;
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
