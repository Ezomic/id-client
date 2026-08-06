<?php

declare(strict_types=1);

namespace Thijssensoftware\IdClient\Http\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Carbon;
use Symfony\Component\HttpFoundation\Response;

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

        $this->markLoggedOut((string) $subject);

        return response()->json(['status' => 'ok']);
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

    private function markLoggedOut(string $idpId): void
    {
        /** @var class-string<Model> $model */
        $model = config('id-client.user_model');

        $model::query()
            ->where('idp_id', $idpId)
            ->update(['sso_logged_out_at' => Carbon::now()]);
    }
}
