<?php

namespace Yomafleet\CognitoAuthenticator\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Casts\AsArrayObject;

class CognitoUser extends Model
{
    use SoftDeletes;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'user_id',
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
}
