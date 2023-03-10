<?php

namespace Yomafleet\CognitoAuthenticator;

use Illuminate\Support\Facades\Auth;
use Yomafleet\CognitoAuthenticator\CognitoGuard;
use Yomafleet\CognitoAuthenticator\UserProvider;
use Illuminate\Support\ServiceProvider as BaseProvider;
use Yomafleet\CognitoAuthenticator\CognitoSubRetriever;

class ServiceProvider extends BaseProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        //
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        $this->addCognitoGuard();
        $this->loadMigrations();
        $this->publishConfig();
        $this->createUserProvider();
    }

    protected function addCognitoGuard()
    {
        Auth::extend('cognito', function ($app, $name, array $config) {
            return new CognitoGuard(
                Auth::createUserProvider($config['provider']),
                new CognitoSubRetriever($app['request'])
            );
        });
    }

    protected function loadMigrations()
    {
        $this->loadMigrationsFrom(
            __DIR__ . '/../database/migrations/'
        );
    }

    protected function publishConfig()
    {
        $this->publishes([
            __DIR__.'/../config/cognito.php' => config_path('cognito.php'),
        ]);
    }

    protected function createUserProvider()
    {
        Auth::provider('cognito', function ($app, array $config) {
            return new UserProvider(
                $app['hash'],
                $config['model']
            );
        });
    }
}
