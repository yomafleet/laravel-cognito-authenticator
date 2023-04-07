<?php

namespace Yomafleet\CognitoAuthenticator;

use Yomafleet\CognitoAuthenticator\Exceptions\InvalidStructureException;

class CognitoConfig
{
    /**
     * Get client profile config.
     *
     * @param string $name
     * @param string|null $key
     * @return array|string
     */
    public static function getProfileConfig($name = '', $key = null)
    {
        $defaultClient = config('cognito.default_profile');
        
        if (! $defaultClient) {
            throw new InvalidStructureException('Default client profile not found');
        }

        $clientProfileConfigs = config('cognito.client_profiles');
        $name = $name ? strtolower($name) : $defaultClient;

        if (! isset($clientProfileConfigs[$name])) {
            throw new InvalidStructureException('Client profile config not found: '. $name);
        }

        $config = $clientProfileConfigs[$name];
        $attributes = ['pool_id', 'id', 'secret'];

        foreach ($attributes as $attr) {
            if (! array_key_exists($attr, $config)) {
                throw new InvalidStructureException('Client profile config key missing: '.$attr);
            }
        }

        return in_array($key, $attributes) ? $config[$key] : $config;
    }

    /**
     * Get credentials config.
     *
     * @param string $key
     * @return array
     */
    public static function getCredentials($key = null)
    {
        $credentials = config('cognito.credentials');
        $required = ['key', 'secret'];

        foreach ($required as $attr) {
            if (! array_key_exists($attr, $credentials)) {
                throw new InvalidStructureException('Client profile config key missing: '.$attr);
            }
        }
        return in_array($key, $credentials) ? $credentials[$key] : $credentials;
    }

    /**
     * Get specific config or all
     *
     * @param string $key
     * @return mixed
     */
    public static function get($key = null)
    {
        return $key ? config('cognito.'.$key) : config('cognito');
    }
}
