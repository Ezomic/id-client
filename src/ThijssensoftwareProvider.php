<?php

declare(strict_types=1);

namespace Thijssensoftware\IdClient;

use GuzzleHttp\RequestOptions;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;
use Thijssensoftware\IdClient\Exceptions\AccessDeniedException;

class ThijssensoftwareProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * The separating character for the requested scopes.
     */
    protected $scopeSeparator = ' ';

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->baseUrl().'/oauth/authorize', $state);
    }

    protected function getTokenUrl(): string
    {
        return $this->baseUrl().'/oauth/token';
    }

    /**
     * @param  string  $token
     * @return array<string, mixed>
     */
    protected function getUserByToken($token): array
    {
        $response = $this->getHttpClient()->get($this->baseUrl().'/api/userinfo', [
            RequestOptions::HEADERS => [
                'Authorization' => 'Bearer '.$token,
                'Accept' => 'application/json',
            ],
            RequestOptions::HTTP_ERRORS => false,
        ]);

        $status = $response->getStatusCode();

        if ($status === 403) {
            throw new AccessDeniedException('You do not have access to this application.');
        }

        // An expired token, a throttle or an outage answers with an error body, not
        // a user. Decoded, it maps to a user with no subject, so it is refused here
        // rather than handed on.
        if ($status < 200 || $status >= 300) {
            throw new AccessDeniedException('Thijssensoftware ID could not confirm your access. Please try signing in again.');
        }

        return (array) json_decode((string) $response->getBody(), true);
    }

    /**
     * @param  array<string, mixed>  $user
     */
    protected function mapUserToObject(array $user): User
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['sub'] ?? null,
            'name' => $user['name'] ?? null,
            'email' => $user['email'] ?? null,
            'applications' => $user['applications'] ?? [],
        ]);
    }

    protected function baseUrl(): string
    {
        return rtrim((string) config('services.thijssensoftware.base_url'), '/');
    }
}
