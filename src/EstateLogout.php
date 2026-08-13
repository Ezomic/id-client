<?php

declare(strict_types=1);

namespace Thijssensoftware\IdClient;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Signing out of this app ends this app's session and nothing else, so the next
 * visit to any sibling signs straight back in and the user reasonably believes
 * they logged out. This asks ID to end the rest too.
 *
 * Opt-in: which of the two a consumer offers is its own decision, and plain
 * local logout stays available and unchanged.
 */
final class EstateLogout
{
    /**
     * Returns whether ID accepted the request. A false here means the local
     * session should still end: failing to reach ID is not a reason to keep
     * the user signed in where they asked to be signed out.
     */
    public static function request(): bool
    {
        $token = session('id_client.access_token');

        if (! is_string($token) || $token === '') {
            return false;
        }

        $base = rtrim((string) config('services.thijssensoftware.base_url'), '/');

        try {
            return Http::timeout(5)
                ->withToken($token)
                ->acceptJson()
                ->post($base.'/api/sso/logout')
                ->successful();
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Ends the estate session and then this one, in that order: the access
     * token lives in the session being destroyed.
     */
    public static function perform(): bool
    {
        $accepted = self::request();

        Auth::guard(config('id-client.guard'))->logout();

        return $accepted;
    }
}
