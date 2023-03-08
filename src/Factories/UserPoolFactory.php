<?php

namespace Yomafleet\CognitoAuthenticator\Factories;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Cache;
use Illuminate\Validation\UnauthorizedException;
use Yomafleet\CognitoAuthenticator\Models\UserPool;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolFactoryContract;
use Yomafleet\CognitoAuthenticator\Exceptions\EnvironmentalNotSetException;

class UserPoolFactory implements UserPoolFactoryContract
{
    /** @var string */
    protected $id;

    /** @var string */
    protected $region;

    /** @var array */
    protected $clientIds = [''];

    /**
     * Get user pool ID
     *
     * @return string
     */
    public function getId()
    {
        if (! is_null($this->id)) {
            return $this->id;
        }

        $this->id = config('cognito.pool_id');

        if (! $this->id) {
            throw new EnvironmentalNotSetException(
                "AWS_COGNITO_USER_POOL_ID not found in environmental variables!"
            );
        }

        return $this->id;
    }

    /**
     * Get regino
     *
     * @return string
     */
    public function getRegion()
    {
        if (! is_null($this->region)) {
            return $this->region;
        }

        $this->region = config('cognito.region');

        if (! $this->id) {
            throw new EnvironmentalNotSetException(
                "AWS_REGION not found in environmental variables!"
            );
            
        }

        return $this->region;
    }

    /**
     * Get JWK from cache or from cognito
     *
     * @throws \Illuminate\Validation\UnauthorizedException
     * @return array
     */
    public function getJwk()
    {
        return Cache::get($this->getId(), function () {
            $jwk = $this->fetchJwk();
            Cache::add($this->getId(), $jwk);

            return $jwk;
        });
    }

    /**
     * Fetch JWK from cognito
     *
     * @throws \Illuminate\Validation\UnauthorizedException
     * @return array
     */
    protected function fetchJwk()
    {
        $url = sprintf(
            'https://cognito-idp.ap-southeast-1.amazonaws.com/%s/.well-known/jwks.json',
            $this->getId()
        );

        $response = Http::get($url);

        if (! $response->ok()) {
            throw new UnauthorizedException("Unauthorized!");
        }

        return $response->json();
    }

    /**
     * Create a new UserPool object
     *
     * @param array $clientIds
     * @throws \Illuminate\Validation\UnauthorizedException
     * @return \Yomafleet\CognitoAuthenticator\Models\UserPool
     */
    public function create(array $clientIds = ['']): UserPool
    {
        return new UserPool(
            $this->getId(),
            $clientIds,
            $this->getRegion(),
            $this->getJwk(),
        );
    }
}
