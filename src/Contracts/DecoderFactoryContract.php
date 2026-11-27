<?php

namespace Yomafleet\CognitoAuthenticator\Contracts;

interface DecoderFactoryContract
{
    /**
     * Create an instance of DecoderFactoryContract.
     *
     * @return \Yomafleet\CognitoAuthenticator\Contracts\DecoderContract
     */
    public function create(): DecoderContract;
}
