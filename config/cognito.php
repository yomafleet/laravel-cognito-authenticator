<?php

return [
    'credentials'       => [
        'key'    => env('AWS_ACCESS_KEY_ID', ''),
        'secret' => env('AWS_SECRET_ACCESS_KEY', ''),
    ],
    'region' => env('AWS_COGNITO_REGION'),
    'id_token_name' => env('AWS_COGNITO_ID_TOKEN_NAME', 'X-ID-Token'),
    'client_ids' => env('AWS_COGNITO_CLIENT_IDS', ''),
    'version' => env('AWS_COGNITO_VERSION', 'latest'),

    'default_profile' => 'main',

    'client_profiles' => [
        'main' => [
            'pool_id' => env('AWS_COGNITO_USER_POOL_ID'),
            'id' => env('AWS_COGNITO_CLIENT_ID'),
            'secret' => env('AWS_COGNITO_CLIENT_SECRET'),
        ],
    ]
];
