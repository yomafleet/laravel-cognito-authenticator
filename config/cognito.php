<?php

return [
    'credentials'       => [
        'key'    => env('AWS_ACCESS_KEY_ID', ''),
        'secret' => env('AWS_SECRET_ACCESS_KEY', ''),
    ],
    'pool_id' => env('AWS_COGNITO_USER_POOL_ID'),
    'region' => env('AWS_DEFAULT_REGION'),
    'id_token_name' => env('AWS_COGNITO_ID_TOKEN_NAME', 'X-ID-Token'),
    'client_ids' => env('AWS_COGNITO_CLIENT_IDS', ''),
    'id' => env('AWS_COGNITO_CLIENT_ID'),
    'secret' => env('AWS_COGNITO_CLIENT_SECRET'),
    'version' => env('AWS_COGNITO_VERSION', 'latest'),
];
