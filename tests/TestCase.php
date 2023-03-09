<?php

namespace Tests;

abstract class TestCase extends \Orchestra\Testbench\TestCase
{
    protected function getPackageProviders($app)
    {
        return [
            \Yomafleet\CognitoAuthenticator\ServiceProvider::class,
        ];
    }
}
