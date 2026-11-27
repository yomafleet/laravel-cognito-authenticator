<?php

namespace Yomafleet\CognitoAuthenticator\Models;

use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;
use Yomafleet\CognitoAuthenticator\Exceptions\TokenException;

abstract class Token implements TokenContract
{
    /**
     * @var array
     */
    private $claims;

    /**
     * Token constructor.
     *
     * @param  array  $claims
     */
    public function __construct(array $claims)
    {
        $this->claims = $claims;
    }

    /**
     * Get all claims.
     *
     * @return array
     */
    public function claims()
    {
        return $this->claims;
    }

    /**
     * Get a claim value for the token.
     *
     * @param  string  $name
     * @return mixed
     */
    public function getClaim($name)
    {
        if (isset($this->claims[$name])) {
            return $this->claims[$name];
        }
    }

    /**
     * Get a "sub" claim from the token.
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\TokenException
     * @return mixed
     */
    public function getSub()
    {
        if ($sub = $this->getClaim('sub')) {
            return $sub;
        }

        throw new TokenException("Identifier `sub` not found!");
        
    }
}
