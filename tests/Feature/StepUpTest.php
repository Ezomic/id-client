<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Contracts\Factory as Socialite;
use Laravel\Socialite\Contracts\Provider;
use Laravel\Socialite\Two\User as SocialiteUser;
use Thijssensoftware\IdClient\Http\Middleware\EnsureSsoSessionIsActive;
use Thijssensoftware\IdClient\StepUp;
use Thijssensoftware\IdClient\Tests\Fixtures\User;

/**
 * @param  array<string, mixed>  $claims
 */
function idToken(array $claims): string
{
    $encode = fn (array $part): string => rtrim(strtr(base64_encode((string) json_encode($part)), '+/', '-_'), '=');

    return $encode(['alg' => 'RS256']).'.'.$encode($claims).'.signature';
}

/**
 * @param  array<string, mixed>  $overrides
 */
function stepUpClaims(array $overrides = []): array
{
    return array_merge([
        'iss' => 'https://id.example.test',
        'aud' => 'test-client-id',
        'sub' => 'idp-1',
        'auth_time' => Carbon::now()->getTimestamp(),
    ], $overrides);
}

function stepUpIdUser(?string $idToken, string $id = 'idp-1'): SocialiteUser
{
    return (new SocialiteUser)->map([
        'id' => $id,
        'name' => 'Robbin',
        'email' => 'robbin@example.test',
        'id_token' => $idToken,
    ]);
}

function stepUpDriver(SocialiteUser $user): void
{
    $driver = Mockery::mock(Provider::class);
    $driver->shouldReceive('user')->andReturn($user);

    $factory = Mockery::mock(Socialite::class);
    $factory->shouldReceive('driver')->with('thijssensoftware')->andReturn($driver);

    app()->instance(Socialite::class, $factory);
}

function signedInUser(string $idpId = 'idp-1'): User
{
    $user = User::create(['name' => 'Robbin', 'email' => $idpId.'@example.test', 'idp_id' => $idpId]);
    test()->actingAs($user)->withSession([]);
    request()->setLaravelSession(app('session.store'));

    return $user;
}

function authorizeQuery(string $url): array
{
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    return $query;
}

it('asks ID for a recent authentication with max_age and the openid scope', function (): void {
    signedInUser();

    $query = authorizeQuery(StepUp::url(300));

    expect(StepUp::url(300))->toStartWith('https://id.example.test/oauth/authorize?')
        ->and($query)->toHaveKey('max_age', '300')
        ->and($query['scope'])->toBe('openid')
        ->and($query)->not->toHaveKey('prompt');
});

it('never sends prompt=login, which would end the ID session', function (): void {
    signedInUser();

    expect(StepUp::url(300))->not->toContain('prompt');
});

it('refuses to ask for a step-up on behalf of nobody', function (): void {
    StepUp::url(300);
})->throws(LogicException::class);

it('refuses a max_age ID would refuse', function (int $seconds): void {
    signedInUser();

    StepUp::url($seconds);
})->throws(InvalidArgumentException::class)->with([0, -1, 29, 86401, PHP_INT_MAX, PHP_INT_MIN]);

it('returns a redirect to the same url', function (): void {
    signedInUser();

    expect(StepUp::redirect(120)->getTargetUrl())->toContain('max_age=120');
});

it('records the auth_time ID vouches for and leaves the user signed in', function (): void {
    $user = signedInUser();
    $now = Carbon::now()->getTimestamp();
    StepUp::url(300);
    stepUpDriver(stepUpIdUser(idToken(stepUpClaims(['auth_time' => $now - 40]))));

    $this->get('auth/sso/callback')->assertRedirect('/dashboard');

    expect(Auth::id())->toBe($user->id)
        ->and(session('id_client.auth_time'))->toBe($now - 40)
        ->and(StepUp::satisfied(300))->toBeTrue()
        ->and(StepUp::satisfied(30))->toBeFalse();
});

it('refuses to count a silent bounce, where ID sends no auth_time', function (): void {
    signedInUser();
    StepUp::url(300);
    $claims = stepUpClaims();
    unset($claims['auth_time']);
    stepUpDriver(stepUpIdUser(idToken($claims)));

    $this->get('auth/sso/callback')->assertForbidden();

    expect(session('id_client.auth_time'))->toBeNull()
        ->and(StepUp::satisfied(300))->toBeFalse();
});

it('refuses when ID sends no id token at all, as an ID without step-up would', function (?string $token): void {
    signedInUser();
    StepUp::url(300);
    stepUpDriver(stepUpIdUser($token));

    $this->get('auth/sso/callback')->assertForbidden();

    expect(StepUp::satisfied(300))->toBeFalse();
})->with([[null], [''], ['not-a-jwt'], ['a.b'], ['a.!!!.c']]);

it('refuses an auth_time older than the max_age that was asked for', function (): void {
    signedInUser();
    StepUp::url(60);
    stepUpDriver(stepUpIdUser(idToken(stepUpClaims(['auth_time' => Carbon::now()->getTimestamp() - 300]))));

    $this->get('auth/sso/callback')->assertForbidden();

    expect(StepUp::satisfied(300))->toBeFalse();
});

it('refuses an auth_time in the future', function (): void {
    signedInUser();
    StepUp::url(300);
    stepUpDriver(stepUpIdUser(idToken(stepUpClaims(['auth_time' => Carbon::now()->getTimestamp() + 3600]))));

    $this->get('auth/sso/callback')->assertForbidden();
});

it('refuses an auth_time that is not a whole number', function (mixed $authTime): void {
    signedInUser();
    StepUp::url(300);
    stepUpDriver(stepUpIdUser(idToken(stepUpClaims(['auth_time' => $authTime]))));

    $this->get('auth/sso/callback')->assertForbidden();
})->with([['now'], [null], [true], [[1]], [-1], [0], [1.5], ['1792000000']]);

it('refuses an id token minted for another client', function (): void {
    signedInUser();
    StepUp::url(300);
    stepUpDriver(stepUpIdUser(idToken(stepUpClaims(['aud' => 'someone-else']))));

    $this->get('auth/sso/callback')->assertForbidden();
});

it('accepts an audience list that includes this client', function (): void {
    signedInUser();
    StepUp::url(300);
    stepUpDriver(stepUpIdUser(idToken(stepUpClaims(['aud' => ['other', 'test-client-id']]))));

    $this->get('auth/sso/callback')->assertRedirect('/dashboard');
});

it('refuses an id token about a different user than the one asking', function (): void {
    $alice = signedInUser('idp-alice');
    StepUp::url(300);
    stepUpDriver(stepUpIdUser(idToken(stepUpClaims(['sub' => 'idp-bob'])), id: 'idp-bob'));
    User::create(['name' => 'Bob', 'email' => 'bob@example.test', 'idp_id' => 'idp-bob']);

    $this->get('auth/sso/callback')->assertForbidden();

    expect(Auth::id())->toBe($alice->id);
});

it('refuses a token whose sub does not match the userinfo it came with', function (): void {
    signedInUser();
    StepUp::url(300);
    stepUpDriver(stepUpIdUser(idToken(stepUpClaims(['sub' => 'idp-other']))));

    $this->get('auth/sso/callback')->assertForbidden();
});

it('does not let one request satisfy a second step-up', function (): void {
    signedInUser();
    StepUp::url(300);
    stepUpDriver(stepUpIdUser(idToken(stepUpClaims())));
    $this->get('auth/sso/callback')->assertRedirect('/dashboard');

    // The stored request is spent. A callback with no request pending is an
    // ordinary sign-in and records no auth_time of its own.
    session()->forget('id_client.auth_time');
    stepUpDriver(stepUpIdUser(idToken(stepUpClaims())));
    $this->get('auth/sso/callback')->assertRedirect('/dashboard');

    expect(session('id_client.auth_time'))->toBeNull();
});

it('forgets a step-up that was started and then abandoned when a plain sign-in begins', function (): void {
    signedInUser();
    StepUp::url(300);

    $this->get('auth/sso/redirect')->assertRedirectContains('https://id.example.test/oauth/authorize');
    stepUpDriver(stepUpIdUser(null));

    $this->get('auth/sso/callback')->assertRedirect('/dashboard');
});

it('reports not satisfied when no step-up ever happened', function (): void {
    signedInUser();

    expect(StepUp::satisfied(300))->toBeFalse();
});

it('reports not satisfied once the auth_time has aged out', function (): void {
    signedInUser();
    StepUp::url(300);
    stepUpDriver(stepUpIdUser(idToken(stepUpClaims())));
    $this->get('auth/sso/callback');

    expect(StepUp::satisfied(60))->toBeTrue();

    Carbon::setTestNow(Carbon::now()->addSeconds(61));

    expect(StepUp::satisfied(60))->toBeFalse();

    Carbon::setTestNow();
});

it('never reports a window of zero or less as satisfied', function (): void {
    signedInUser();
    StepUp::url(300);
    stepUpDriver(stepUpIdUser(idToken(stepUpClaims())));
    $this->get('auth/sso/callback');

    expect(StepUp::satisfied(0))->toBeFalse()
        ->and(StepUp::satisfied(-5))->toBeFalse();
});

it('leaves an ordinary sign-in alone', function (): void {
    $user = User::create(['name' => 'Robbin', 'email' => 'robbin@example.test', 'idp_id' => 'idp-1']);
    stepUpDriver(stepUpIdUser(null));

    $this->get('auth/sso/callback')->assertRedirect('/dashboard');

    expect(Auth::id())->toBe($user->id)
        ->and(session('id_client.auth_time'))->toBeNull()
        ->and(session(EnsureSsoSessionIsActive::AUTHENTICATED_AT))->not->toBeNull();
});
