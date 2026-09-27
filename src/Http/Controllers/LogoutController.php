<?php

declare(strict_types=1);

namespace Thijssensoftware\IdClient\Http\Controllers;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use Thijssensoftware\IdClient\Events\AccessRevoked;

class LogoutController extends Controller
{
    /**
     * A signed call from Thijssensoftware ID saying the user signed out there.
     * Arrives server-to-server with no session cookie, so it stamps the user
     * row and EnsureSsoSessionIsActive does the sign-out on the next request.
     */
    public function __invoke(Request $request): JsonResponse
    {
        $secret = config('id-client.logout_secret');

        if (! is_string($secret) || $secret === '') {
            // Not configured means the consumer has not been redeployed with
            // the shared secret yet. Say so rather than accepting unsigned calls.
            return response()->json(['error' => 'single_logout_not_configured'], Response::HTTP_NOT_IMPLEMENTED);
        }

        $body = $request->getContent();
        $signature = (string) $request->header('X-Id-Signature', '');

        if (! hash_equals(hash_hmac('sha256', $body, $secret), $signature)) {
            return response()->json(['error' => 'invalid_signature'], Response::HTTP_UNAUTHORIZED);
        }

        $payload = json_decode($body, true);

        if (! is_array($payload) || ! $this->isFresh($payload)) {
            return response()->json(['error' => 'invalid_request'], Response::HTTP_BAD_REQUEST);
        }

        $subject = $payload['sub'] ?? null;

        if (! is_string($subject) && ! is_int($subject)) {
            return response()->json(['error' => 'invalid_request'], Response::HTTP_BAD_REQUEST);
        }

        // Absent means a pre-0.3 server, which only ever sent logouts.
        $event = $payload['event'] ?? 'logout';

        return match ($event) {
            'logout' => $this->endSession((string) $subject),
            'access.revoked' => $this->revokeAccess((string) $subject),
            'user.updated' => $this->refreshUser((string) $subject, $payload),
            // An unknown type from a newer ID must not error, or upgrading the
            // server would break every consumer that has not caught up yet.
            default => response()->json(['status' => 'ignored']),
        };
    }

    /**
     * A correctly signed body is still replayable forever without this.
     *
     * @param  array<mixed>  $payload
     */
    private function isFresh(array $payload): bool
    {
        $issuedAt = $payload['issued_at'] ?? null;

        if (! is_int($issuedAt)) {
            return false;
        }

        return abs(Carbon::now()->getTimestamp() - $issuedAt) <= 300;
    }

    /**
     * Sign-in always sets a remember-me cookie, and a session that cookie
     * restores after the logout is stamped later than the logout, so the stamp
     * alone would let the cookie outlive it. Cycling the token, as Laravel's
     * own logout does, is what ends it.
     */
    private function endSession(string $idpId): JsonResponse
    {
        $users = $this->users();
        $attributes = ['sso_logged_out_at' => Carbon::now()];
        $rememberTokenColumn = $users->getModel()->getRememberTokenName();

        // An empty name is how a model opts out of remember tokens.
        if (! empty($rememberTokenColumn)) {
            $attributes[$rememberTokenColumn] = Str::random(60);
        }

        $users->where('idp_id', $idpId)->update($attributes);

        return response()->json(['status' => 'ok']);
    }

    /**
     * The stamp only ends the web session, so an app that issued anything else,
     * such as API tokens, needs to hear about it. Deliberately not on logout:
     * ID sends that per session, and tying tokens to it would kill a script
     * every time the user signs out on another machine.
     */
    private function revokeAccess(string $idpId): JsonResponse
    {
        $response = $this->endSession($idpId);

        foreach ($this->users()->where('idp_id', $idpId)->get() as $user) {
            AccessRevoked::dispatch($user);
        }

        return $response;
    }

    /**
     * A consumer writes its copy of the user once at the OAuth callback and
     * never updates it, so without this a name or email changed at ID stays
     * stale here indefinitely.
     *
     * @param  array<mixed>  $payload
     */
    private function refreshUser(string $idpId, array $payload): JsonResponse
    {
        $attributes = array_filter([
            'name' => is_string($payload['name'] ?? null) ? $payload['name'] : null,
            'email' => is_string($payload['email'] ?? null) ? $payload['email'] : null,
        ], fn (?string $value): bool => $value !== null && $value !== '');

        if ($attributes !== []) {
            $this->users()->where('idp_id', $idpId)->update($attributes);
        }

        return response()->json(['status' => 'ok']);
    }

    /**
     * @return Builder<Model>
     */
    private function users()
    {
        /** @var class-string<Model> $model */
        $model = config('id-client.user_model');

        return $model::query();
    }
}
