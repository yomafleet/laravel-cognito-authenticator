<?php

namespace Yomafleet\CognitoAuthenticator;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use \Illuminate\Contracts\Auth\UserProvider;
use Yomafleet\CognitoAuthenticator\Contracts\CanGetSubContract;

class CognitoGuard implements Guard
{
    use GuardHelpers;

    public const IDENTIFIER_NAME = 'sub';

    /** @var string|null */
    protected $sub;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\CanGetSubContract */
    protected $subRetriever;

    public function __construct(UserProvider $provider, CanGetSubContract $subRetriever)
    {
        $this->provider = $provider;
        $this->subRetriever = $subRetriever;
    }

    protected function sub()
    {
        if (! is_null($this->sub)) {
            return $this->sub;
        }

        $this->sub = $this->subRetriever->getSub();

        return $this->sub;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (! is_null($this->user)) {
            return $this->user;
        }

        if (! $this->sub()) {
            return null;
        }

        $this->user = $this->provider->retrieveByCredentials([
            self::IDENTIFIER_NAME => $this->sub()
        ]);

        return $this->user;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        if (empty($credentials[self::IDENTIFIER_NAME])) {
            return false;
        }

        $credentials = [self::IDENTIFIER_NAME => $credentials[self::IDENTIFIER_NAME]];

        if ($this->provider->retrieveByCredentials($credentials)) {
            return true;
        }

        return false;
    }
}
