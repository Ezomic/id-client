<?php

declare(strict_types=1);

namespace Thijssensoftware\IdClient;

use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use InvalidArgumentException;
use Laravel\Socialite\Contracts\Factory as Socialite;
use LogicException;
use Thijssensoftware\IdClient\Exceptions\StepUpFailedException;

/**
 * Asks ID to prove that the person at the keyboard has just re-entered a
 * credential, without ending their ID session. `prompt=login` would do it, and
 * would also sign the user out of every app, so this uses OIDC `max_age`
 * instead and trusts only the `auth_time` ID signs into the ID token.
 *
 * A bounce through ID that finds a live session proves the browser holds a
 * session, not that the person is there. That never counts here: no `auth_time`
 * from ID, or one older than asked for, fails the sign-in rather than falling
 * back to the silent kind.
 */
final class StepUp
{
    public const MIN_SECONDS = 30;

    public const MAX_SECONDS = 86400;

    public const REQUEST = 'id_client.step_up';

    public const AUTH_TIME = 'id_client.auth_time';

    /**
     * Allowance for the two clocks disagreeing, in seconds.
     */
    private const SKEW = 10;

    /**
     * The URL to send the user to. The requirement is fixed here, in the app's
     * own code and session, and never read back from anything the browser can
     * edit: a link carrying its own window would let a stolen session ask for a
     * generous one.
     */
    public static function url(int $maxAge): string
    {
        if ($maxAge < self::MIN_SECONDS || $maxAge > self::MAX_SECONDS) {
            throw new InvalidArgumentException('max_age must be between '.self::MIN_SECONDS.' and '.self::MAX_SECONDS.' seconds.');
        }

        $user = Auth::guard(config('id-client.guard'))->user();
        $idpId = $user?->getAttribute('idp_id');

        if (! is_string($idpId) || $idpId === '') {
            throw new LogicException('A step-up needs a signed-in user who has an idp_id.');
        }

        $target = app(Socialite::class)->driver('thijssensoftware')
            ->scopes(['openid'])
            ->with(['max_age' => $maxAge])
            ->redirect();

        session([self::REQUEST => ['max_age' => $maxAge, 'idp_id' => $idpId]]);

        return $target->getTargetUrl();
    }

    public static function redirect(int $maxAge): RedirectResponse
    {
        return redirect()->away(self::url($maxAge));
    }

    /**
     * True when ID vouched, within the last `$maxAge` seconds, that this user
     * re-entered a credential. Compared against this app's own clock.
     */
    public static function satisfied(int $maxAge): bool
    {
        $authTime = session(self::AUTH_TIME);

        if ($maxAge < 1 || ! is_int($authTime)) {
            return false;
        }

        $age = Carbon::now()->getTimestamp() - $authTime;

        return $age >= 0 && $age <= $maxAge;
    }

    /**
     * Called by the callback when a step-up is pending. Returns the verified
     * `auth_time`.
     *
     * The token arrives from ID's token endpoint over TLS in answer to this
     * app's own authenticated request, which is why its signature is not
     * checked again (OIDC Core 3.1.3.7).
     *
     * @param  array{max_age: int, idp_id: string}  $request
     *
     * @throws StepUpFailedException
     */
    public static function complete(array $request, string $subject, mixed $idToken): int
    {
        if ($subject !== $request['idp_id']) {
            throw new StepUpFailedException('ID answered for a different user than the one who asked.');
        }

        $claims = self::claims($idToken);

        if (($claims['sub'] ?? null) !== $request['idp_id']) {
            throw new StepUpFailedException('The ID token is about a different user.');
        }

        if (! self::isForThisClient($claims['aud'] ?? null)) {
            throw new StepUpFailedException('The ID token was issued to another client.');
        }

        $authTime = $claims['auth_time'] ?? null;

        if (! is_int($authTime) || $authTime < 1) {
            throw new StepUpFailedException('ID did not confirm a recent authentication.');
        }

        $age = Carbon::now()->getTimestamp() - $authTime;

        if ($age < -self::SKEW || $age > $request['max_age'] + self::SKEW) {
            throw new StepUpFailedException('The authentication ID confirmed is not recent enough.');
        }

        return $authTime;
    }

    /**
     * @return array<string, mixed>
     */
    private static function claims(mixed $idToken): array
    {
        $parts = is_string($idToken) ? explode('.', $idToken) : [];

        if (count($parts) !== 3) {
            throw new StepUpFailedException('ID sent no ID token.');
        }

        $payload = base64_decode(strtr($parts[1], '-_', '+/'), true);
        $claims = $payload === false ? null : json_decode($payload, true);

        if (! is_array($claims)) {
            throw new StepUpFailedException('The ID token could not be read.');
        }

        return $claims;
    }

    private static function isForThisClient(mixed $audience): bool
    {
        $clientId = config('services.thijssensoftware.client_id');

        if (! is_string($clientId) || $clientId === '') {
            return false;
        }

        return is_array($audience) ? in_array($clientId, $audience, true) : $audience === $clientId;
    }
}
