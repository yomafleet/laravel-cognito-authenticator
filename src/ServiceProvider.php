<?php

namespace Yomafleet\CognitoAuthenticator;

use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Auth;
use Yomafleet\CognitoAuthenticator\CognitoGuard;
use Yomafleet\CognitoAuthenticator\UserProvider;
use Illuminate\Support\ServiceProvider as BaseProvider;

class ServiceProvider extends BaseProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->registerManager();
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        $this->loadMigrations();
        $this->publishConfig();
        $this->createUserProvider();
        $this->addCognitoGuard();
    }

    protected function registerManager()
    {
        $this->app->bind('cognito-authenticator', function () {
            $this->createManager();
        });
    }

    protected function addCognitoGuard()
    {
        Auth::extend('cognito', function ($app, $name, array $config) {
            $manager = $this->createManager();

            return new CognitoGuard(
                Auth::createUserProvider($config['provider']),
                $manager->getSubRetriever($app['request']),
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

    protected function createManager()
    {
        $clientIds = config('cognito.client_ids', '');
        $clientIds = explode(',', $clientIds);
        return new CognitoManager($clientIds);
    }
}
