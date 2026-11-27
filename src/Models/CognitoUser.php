<?php

namespace Yomafleet\CognitoAuthenticator\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Casts\AsArrayObject;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Yomafleet\CognitoAuthenticator\Factories\CognitoUserFactory;

class CognitoUser extends Model
{
    use SoftDeletes;
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'subable_type',
        'subable_id',
        'sub',
        'identities',
    ];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'identities' => AsArrayObject::class,
    ];

    /**
     * Get the parent subable model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo
     */
    public function subable()
    {
        return $this->morphTo();
    }

    /**
     * Create a new factory instance for the model.
     */
    protected static function newFactory(): Factory
    {
        return CognitoUserFactory::new();
    }
}
