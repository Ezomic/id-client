<?php

declare(strict_types=1);

namespace Thijssensoftware\IdClient\Tests\Fixtures;

use Laravel\Socialite\Two\User as SocialiteUser;
use Thijssensoftware\IdClient\ThijssensoftwareProvider;

/**
 * Every interesting method on the provider is protected, because that is the shape
 * Socialite's AbstractProvider dictates. This exposes them so they can be asserted
 * on directly rather than only through a full OAuth round trip.
 */
class ExposedProvider extends ThijssensoftwareProvider
{
    public function authUrl(string $state): string
    {
        return $this->getAuthUrl($state);
    }

    public function tokenUrl(): string
    {
        return $this->getTokenUrl();
    }

    /**
     * @return array<string, mixed>
     */
    public function userByToken(string $token): array
    {
        return $this->getUserByToken($token);
    }

    /**
     * @param  array<string, mixed>  $user
     */
    public function mapUser(array $user): SocialiteUser
    {
        return $this->mapUserToObject($user);
    }
}
