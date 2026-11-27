# Laravel Cognito Authenticator

Authentication with AWS Cognito for Laravel projects.

## Requirements

- PHP 8.2 or higher
- Laravel 12.x
- AWS Cognito User Pool

## Installation

Install with composer:

```bash
composer require yomafleet/cognito-authenticator
```

The service provider will be automatically registered.

## Configuration

### 1. Update Auth Guard

Set the 'driver' option of the 'guards' in `config/auth.php` to 'cognito':

```php
'guards' => [
    'api' => [
        'driver'   => 'cognito',
        'provider' => 'users',
        'hash'     => false,
    ],
],
```

### 2. Environment Variables

Add the following to your `.env` file:

```env
AWS_COGNITO_USER_POOL_ID=your-user-pool-id
AWS_COGNITO_REGION=ap-southeast-1
AWS_COGNITO_CLIENT_ID=your-client-id
AWS_COGNITO_CLIENT_SECRET=your-client-secret
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
```

### 3. Database Migration

**Note:** This package will add 2 new columns to your users table:
- `sub` (string) - Cognito user identifier
- `identities` (json) - User identity information

## Features

- **AWS Cognito Integration**: Seamless authentication with AWS Cognito User Pools
- **JWT Token Validation**: Automatic JWT token verification and validation
- **User Provider**: Custom user provider for Cognito-authenticated users
- **Laravel 12 Optimized**: Built specifically for Laravel 12

## Testing

Run the test suite:

```bash
./vendor/bin/phpunit
```

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
