<?php

namespace Yomafleet\CognitoAuthenticator;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Yomafleet\CognitoAuthenticator\Models\CognitoUser;
use Illuminate\Contracts\Auth\UserProvider as UserProviderContract;

class UserProvider extends EloquentUserProvider implements UserProviderContract
{
    /**
     * {@inheritDoc}
     */
    public function retrieveByCredentials(array $credentials)
    {
        if (isset($credentials['sub'])) {
            return $this->retrieveBySubViaCognitoRelation($credentials['sub']);
        }

        return parent::retrieveByCredentials($credentials);
    }

    /**
     * Retrieve a user by 'sub' from cognito_users table.
     *
     * @param string $sub
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    protected function retrieveBySubViaCognitoRelation(string $sub)
    {
        $cognitoUser = CognitoUser::with('subable')->where('sub', $sub)->first();

        return $cognitoUser->subable ?? null;
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        if (isset($credentials['sub'])) {
            $subbed = $this->retrieveBySubViaCognitoRelation($credentials['sub']);

            return is_a($subbed, Authenticatable::class)
                ? $subbed->getAuthIdentifier() === $user->getAuthIdentifier()
                : false;
        }

        return parent::validateCredentials($user, $credentials);
    }
}
