<?php

return [
    'pool_id' => env('AWS_COGNITO_USER_POOL_ID'),
    'region' => env('AWS_REGION'),
    'id_token_name' => env('AWS_COGNITO_ID_TOKEN_NAME', 'X-ID-Token'),
    'client_ids' => env('AWS_COGNITO_CLIENT_IDS', ''),
];
