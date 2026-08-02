<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Laravel\Socialite\Two\User as SocialiteUser;
use Thijssensoftware\IdClient\Exceptions\AccessDeniedException;
use Thijssensoftware\IdClient\Tests\Fixtures\ExposedProvider;

function provider(Response ...$responses): ExposedProvider
{
    $provider = new ExposedProvider(
        request(), 'test-client-id', 'test-client-secret', 'https://app.example.test/auth/sso/callback'
    );

    if ($responses !== []) {
        $provider->setHttpClient(new Client([
            'handler' => HandlerStack::create(new MockHandler($responses)),
        ]));
    }

    return $provider;
}

it('points the authorize url at the configured id server', function (): void {
    $url = provider()->authUrl('some-state');

    expect($url)->toStartWith('https://id.example.test/oauth/authorize?')
        ->and($url)->toContain('client_id=test-client-id')
        ->and($url)->toContain('state=some-state');
});

it('points the token url at the configured id server', function (): void {
    expect(provider()->tokenUrl())->toBe('https://id.example.test/oauth/token');
});

it('does not double up the slash when the base url has a trailing one', function (): void {
    config()->set('services.thijssensoftware.base_url', 'https://id.example.test/');

    expect(provider()->tokenUrl())->toBe('https://id.example.test/oauth/token');
});

// The space separator is what the id server's OAuth endpoint expects; query encoding
// then renders it as '+'. Socialite's default separator is a comma, so this matters.
it('separates scopes with a space rather than a comma', function (): void {
    $url = provider()->scopes(['openid', 'profile'])->authUrl('s');

    expect($url)->toContain('scope=openid+profile')
        ->and($url)->not->toContain('openid%2Cprofile');
});

it('reads the user from the userinfo endpoint', function (): void {
    $payload = ['sub' => 'idp-1', 'name' => 'Robbin', 'email' => 'robbin@example.test'];

    $user = provider(new Response(200, [], (string) json_encode($payload)))->userByToken('a-token');

    expect($user)->toBe($payload);
});

it('rejects a user the id server says has no access to this app', function (): void {
    provider(new Response(403, [], '{"message":"nope"}'))->userByToken('a-token');
})->throws(AccessDeniedException::class, 'You do not have access to this application.');

it('maps the userinfo payload onto a socialite user', function (): void {
    $user = provider()->mapUser([
        'sub' => 'idp-1',
        'name' => 'Robbin',
        'email' => 'robbin@example.test',
        'applications' => ['billr', 'tracker'],
    ]);

    expect($user)->toBeInstanceOf(SocialiteUser::class)
        ->and($user->getId())->toBe('idp-1')
        ->and($user->getName())->toBe('Robbin')
        ->and($user->getEmail())->toBe('robbin@example.test')
        ->and($user->applications)->toBe(['billr', 'tracker']);
});

it('tolerates a userinfo payload with fields missing', function (): void {
    $user = provider()->mapUser(['sub' => 'idp-1']);

    expect($user->getId())->toBe('idp-1')
        ->and($user->getName())->toBeNull()
        ->and($user->getEmail())->toBeNull()
        ->and($user->applications)->toBe([]);
});

it('keeps the raw payload on the mapped user', function (): void {
    $payload = ['sub' => 'idp-1', 'unmapped' => 'kept'];

    expect(provider()->mapUser($payload)->getRaw())->toBe($payload);
});
