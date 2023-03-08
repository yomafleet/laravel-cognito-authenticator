# laravel-cognito-authenticator

## Install

-   install with composer

```bash
composer require laravel-cognito-authenticator
```

-   set the 'driver' option of the 'guards' in 'config/auth.php' to 'cognito'

```php
[
    'api' => [
            'driver'   => 'cognito',
            'provider' => 'users',
            'hash'     => false,
        ],
]
```

-   Note that this package will add 2 new columns to users table, named: 'sub' and 'identities'

## Testing

```bash
$ ./vendor/bin/phpunit
```

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
