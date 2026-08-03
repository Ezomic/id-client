<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Contracts\Factory as Socialite;
use Laravel\Socialite\Contracts\Provider;
use Laravel\Socialite\Two\User as SocialiteUser;
use Thijssensoftware\IdClient\Exceptions\AccessDeniedException;
use Thijssensoftware\IdClient\Tests\Fixtures\User;

function idUser(string $id = 'idp-1', ?string $name = 'Robbin', ?string $email = 'robbin@example.test'): SocialiteUser
{
    return (new SocialiteUser)->map(['id' => $id, 'name' => $name, 'email' => $email]);
}

/**
 * Swaps the socialite driver for one that returns the given user, or throws the
 * given exception, when the callback asks for it.
 */
function fakeDriver(SocialiteUser|Throwable $result): void
{
    $driver = Mockery::mock(Provider::class);

    $result instanceof Throwable
        ? $driver->shouldReceive('user')->andThrow($result)
        : $driver->shouldReceive('user')->andReturn($result);

    $factory = Mockery::mock(Socialite::class);
    $factory->shouldReceive('driver')->with('thijssensoftware')->andReturn($driver);

    app()->instance(Socialite::class, $factory);
}

it('sends the visitor to the id server to sign in', function (): void {
    $response = $this->get('auth/sso/redirect');

    $response->assertRedirectContains('https://id.example.test/oauth/authorize')
        ->assertRedirectContains('client_id=test-client-id');
});

it('logs in an existing user matched on idp id', function (): void {
    $user = User::create(['name' => 'Old Name', 'email' => 'old@example.test', 'idp_id' => 'idp-1']);

    fakeDriver(idUser());

    $this->get('auth/sso/callback')->assertRedirect('/dashboard');

    expect(Auth::id())->toBe($user->id)
        ->and($user->fresh()->email)->toBe('robbin@example.test');
});

it('adopts an existing user matched on email and backfills the idp id', function (): void {
    $user = User::create(['name' => 'Robbin', 'email' => 'robbin@example.test']);

    fakeDriver(idUser());

    $this->get('auth/sso/callback')->assertRedirect('/dashboard');

    expect(Auth::id())->toBe($user->id)
        ->and($user->fresh()->idp_id)->toBe('idp-1');
});

it('provisions a user who has never signed in here before', function (): void {
    fakeDriver(idUser());

    $this->get('auth/sso/callback')->assertRedirect('/dashboard');

    $user = User::query()->where('idp_id', 'idp-1')->first();

    expect($user)->not->toBeNull()
        ->and($user->email)->toBe('robbin@example.test')
        ->and($user->name)->toBe('Robbin')
        ->and(Auth::id())->toBe($user->id);
});

it('refuses an unknown user when provisioning is off', function (): void {
    config()->set('id-client.provision', false);

    fakeDriver(idUser());

    $this->get('auth/sso/callback')->assertForbidden();

    expect(User::query()->count())->toBe(0)
        ->and(Auth::check())->toBeFalse();
});

it('refuses a user the id server denied access to', function (): void {
    fakeDriver(new AccessDeniedException('You do not have access to this application.'));

    $this->get('auth/sso/callback')->assertForbidden();

    expect(Auth::check())->toBeFalse();
});

it('provisions a first-time user whose idp name is empty', function (): void {
    fakeDriver(idUser(name: ''));

    $this->get('auth/sso/callback')->assertRedirect('/dashboard');

    $user = User::query()->where('idp_id', 'idp-1')->first();

    expect($user)->not->toBeNull()
        ->and($user->name)->toBe('robbin')
        ->and($user->email)->toBe('robbin@example.test')
        ->and(Auth::id())->toBe($user->id);
});

it('provisions a first-time user whose idp name is null', function (): void {
    fakeDriver(idUser(name: null));

    $this->get('auth/sso/callback')->assertRedirect('/dashboard');

    expect(User::query()->first()->name)->toBe('robbin');
});

it('does not bind an unknown identity to an unrelated account with no email', function (): void {
    $other = User::create(['name' => 'Someone Else', 'email' => null, 'idp_id' => 'idp-other']);

    fakeDriver(idUser(id: 'idp-stranger', name: 'Stranger', email: null));

    $this->get('auth/sso/callback')->assertForbidden();

    expect(Auth::check())->toBeFalse()
        ->and($other->fresh()->idp_id)->toBe('idp-other')
        ->and($other->fresh()->name)->toBe('Someone Else')
        ->and(User::query()->count())->toBe(1);
});

it('treats an empty email the same as a missing one', function (): void {
    $other = User::create(['name' => 'Someone Else', 'email' => null, 'idp_id' => 'idp-other']);

    fakeDriver(idUser(id: 'idp-stranger', email: ''));

    $this->get('auth/sso/callback')->assertForbidden();

    expect(Auth::check())->toBeFalse()
        ->and($other->fresh()->idp_id)->toBe('idp-other');
});

it('refuses to provision a user the id server gave no email for', function (): void {
    fakeDriver(idUser(email: null));

    $this->get('auth/sso/callback')->assertForbidden();

    expect(User::query()->count())->toBe(0)
        ->and(Auth::check())->toBeFalse();
});

it('keeps the stored email when a known user signs in without one', function (): void {
    $user = User::create(['name' => 'Robbin', 'email' => 'robbin@example.test', 'idp_id' => 'idp-1']);

    fakeDriver(idUser(email: null));

    $this->get('auth/sso/callback')->assertRedirect('/dashboard');

    expect(Auth::id())->toBe($user->id)
        ->and($user->fresh()->email)->toBe('robbin@example.test');
});

it('keeps the local name when the id server sends an empty one', function (): void {
    User::create(['name' => 'Local Name', 'email' => 'robbin@example.test', 'idp_id' => 'idp-1']);

    fakeDriver(idUser(name: ''));

    $this->get('auth/sso/callback')->assertRedirect('/dashboard');

    expect(User::query()->first()->name)->toBe('Local Name');
});

it('honours the configured home', function (): void {
    config()->set('id-client.home', '/inbox');

    fakeDriver(idUser());

    $this->get('auth/sso/callback')->assertRedirect('/inbox');
});

it('returns the user to where they were headed before signing in', function (): void {
    fakeDriver(idUser());

    $this->withSession(['url.intended' => 'https://app.example.test/reports'])
        ->get('auth/sso/callback')
        ->assertRedirect('https://app.example.test/reports');
});

it('logs the user in on the configured guard', function (): void {
    fakeDriver(idUser());

    $this->get('auth/sso/callback');

    expect(Auth::guard('web')->check())->toBeTrue();
});
