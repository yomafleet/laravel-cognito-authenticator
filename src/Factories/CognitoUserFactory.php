<?php

namespace Yomafleet\CognitoAuthenticator\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Yomafleet\CognitoAuthenticator\Models\CognitoUser;

class CognitoUserFactory extends Factory
{
    /**
     * The name of the factory's corresponding model.
     *
     * @var string
     */
    protected $model = CognitoUser::class;

    /**
     * Define the model's default state.
     *
     * @return array
     */
    public function definition()
    {
        $sub = $this->faker->uuid();

        return [
            'sub' => $sub,
            'identities' => [
                'provider' => 'Cognito',
                'user_id' => $sub,
                'status' => 'EXTERNAL_PROVIDER',
            ],,
        ];
    }
}
