<?php

declare(strict_types=1);

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Testing\TestResponse;
use Thijssensoftware\IdClient\Tests\Fixtures\ExposedProvider;
use Thijssensoftware\IdClient\Tests\Fixtures\User;

/**
 * Runs the real callback with the given userinfo payload. `email_verified` is only
 * part of the payload when passed, so "absent" and "null" stay distinguishable.
 *
 * @param  array<string, mixed>  $claims
 */
function signInThroughId(array $claims): TestResponse
{
    config()->set('services.thijssensoftware.guzzle', [
        'handler' => HandlerStack::create(new MockHandler([
            new Response(200, [], '{"access_token":"a-token","token_type":"Bearer","expires_in":3600}'),
            new Response(200, ['Content-Type' => 'application/json'], (string) json_encode(
                ['sub' => 'idp-1', 'name' => 'Robbin', 'email' => 'admin@example.test', ...$claims],
                JSON_UNESCAPED_SLASHES,
            )),
        ])),
    ]);

    return test()->withSession(['state' => 'a-state'])->get('auth/sso/callback?code=a-code&state=a-state');
}

function localAdmin(string $email = 'admin@example.test'): User
{
    return User::create(['name' => 'The Admin', 'email' => $email]);
}

it('maps email_verified onto the socialite user exactly as given', function (mixed $value): void {
    $provider = new ExposedProvider(request(), 'id', 'secret', 'https://app.example.test/cb');

    expect($provider->mapUser(['sub' => 'idp-1', 'email_verified' => $value])->email_verified)->toBe($value);
})->with([true, false, null, 'false', 0, '', [[]]]);

it('keeps email_verified on the user once the id token has been added', function (): void {
    $provider = new ExposedProvider(request(), 'id', 'secret', 'https://app.example.test/cb');

    $user = $provider->instance(['access_token' => 'a', 'id_token' => 'x.y.z'], ['sub' => 'idp-1', 'email_verified' => false]);

    expect($user->email_verified)->toBeFalse()
        ->and($user->id_token)->toBe('x.y.z');
});

it('maps an absent email_verified to null', function (): void {
    $provider = new ExposedProvider(request(), 'id', 'secret', 'https://app.example.test/cb');

    expect($provider->mapUser(['sub' => 'idp-1'])->email_verified)->toBeNull();
});

it('never signs in as, or changes, a local account matched only by an unverified email', function (): void {
    $admin = localAdmin();

    signInThroughId(['email_verified' => false]);

    expect(Auth::check())->toBeFalse()
        ->and(User::query()->count())->toBe(1)
        ->and($admin->fresh()->idp_id)->toBeNull()
        ->and($admin->fresh()->email)->toBe('admin@example.test')
        ->and($admin->fresh()->name)->toBe('The Admin');
});

it('refuses with the standard message and no other detail', function (): void {
    localAdmin();

    signInThroughId(['email_verified' => false])->assertForbidden()->assertSee('No account for this user.');
});

it('still signs in a user already linked by idp id when the email is unverified, keeping their email', function (): void {
    $linked = User::create(['name' => 'Old Name', 'email' => 'kept@example.test', 'idp_id' => 'idp-1']);
    $admin = localAdmin();

    signInThroughId(['email_verified' => false]);

    expect(Auth::id())->toBe($linked->id)
        ->and($linked->fresh()->email)->toBe('kept@example.test')
        ->and($linked->fresh()->name)->toBe('Robbin')
        ->and($admin->fresh()->idp_id)->toBeNull();
});

it('does not create a user for an unverified identity when provisioning is on', function (): void {
    config()->set('id-client.provision', true);

    signInThroughId(['email_verified' => false, 'email' => 'new@example.test']);

    expect(Auth::check())->toBeFalse()
        ->and(User::query()->count())->toBe(0);
});

it('links an existing account by email when the email is verified', function (): void {
    $admin = localAdmin();

    signInThroughId(['email_verified' => true]);

    expect(Auth::id())->toBe($admin->id)
        ->and($admin->fresh()->idp_id)->toBe('idp-1');
});

it('provisions a new account when the email is verified', function (): void {
    signInThroughId(['email_verified' => true, 'email' => 'new@example.test']);

    $user = User::query()->where('idp_id', 'idp-1')->first();

    expect($user)->not->toBeNull()
        ->and($user->email)->toBe('new@example.test')
        ->and(Auth::id())->toBe($user->id);
});

it('treats every value other than the boolean false as today and links by email', function (array $claims): void {
    $admin = localAdmin();

    signInThroughId($claims);

    expect(Auth::id())->toBe($admin->id)
        ->and($admin->fresh()->idp_id)->toBe('idp-1');
})->with([
    'absent' => [[]],
    'null' => [['email_verified' => null]],
    'true' => [['email_verified' => true]],
    'string false' => [['email_verified' => 'false']],
    'string true' => [['email_verified' => 'true']],
    'zero' => [['email_verified' => 0]],
    'one' => [['email_verified' => 1]],
    'empty string' => [['email_verified' => '']],
    'empty array' => [['email_verified' => []]],
    'non-empty array' => [['email_verified' => [false]]],
]);

it('treats every value other than the boolean false as today and provisions', function (array $claims): void {
    signInThroughId([...$claims, 'email' => 'new@example.test']);

    expect(User::query()->where('idp_id', 'idp-1')->value('email'))->toBe('new@example.test');
})->with([
    'absent' => [[]],
    'null' => [['email_verified' => null]],
    'string false' => [['email_verified' => 'false']],
    'zero' => [['email_verified' => 0]],
    'empty string' => [['email_verified' => '']],
    'empty array' => [['email_verified' => []]],
]);

it('keeps matching email case-sensitively as the database does, verified or not', function (): void {
    $admin = localAdmin('Admin@Example.test');

    signInThroughId(['email_verified' => true]);

    $created = User::query()->where('idp_id', 'idp-1')->first();

    expect($created)->not->toBeNull()
        ->and($created->id)->not->toBe($admin->id)
        ->and($admin->fresh()->idp_id)->toBeNull();
});

it('refuses an unverified email that matches a stored mixed-case or plus-addressed email exactly', function (string $email): void {
    $admin = localAdmin($email);

    signInThroughId(['email_verified' => false, 'email' => $email]);

    expect(Auth::check())->toBeFalse()
        ->and(User::query()->count())->toBe(1)
        ->and($admin->fresh()->idp_id)->toBeNull();
})->with(['mixed case' => 'Admin@Example.test', 'plus address' => 'admin+x@example.test']);

it('treats a plus-addressed verified email as a different account', function (): void {
    $admin = localAdmin();

    signInThroughId(['email_verified' => true, 'email' => 'admin+x@example.test']);

    expect(Auth::id())->not->toBe($admin->id)
        ->and($admin->fresh()->idp_id)->toBeNull()
        ->and(User::query()->count())->toBe(2);
});

it('refuses an unverified identity with an empty or blank email', function (string $email): void {
    localAdmin();

    signInThroughId(['email_verified' => false, 'email' => $email]);

    expect(Auth::check())->toBeFalse()
        ->and(User::query()->count())->toBe(1);
})->with(['empty' => '', 'whitespace' => '   ']);

it('refuses an unverified identity with a null email', function (): void {
    localAdmin();

    signInThroughId(['email_verified' => false, 'email' => null])->assertForbidden();

    expect(Auth::check())->toBeFalse();
});
