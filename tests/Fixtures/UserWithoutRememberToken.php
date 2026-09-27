<?php

declare(strict_types=1);

namespace Thijssensoftware\IdClient\Tests\Fixtures;

class UserWithoutRememberToken extends User
{
    protected $rememberTokenName = '';
}
