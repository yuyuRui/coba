<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Location extends Model
{
    public function workstations()
    {
        return $this->hasMany('App\Models\Workstation');
    }
}
