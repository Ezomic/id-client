<?php

declare(strict_types=1);

return [
    /*
     | The guard used to log the user in after a successful SSO callback.
     */
    'guard' => env('THIJSSENSOFTWARE_ID_GUARD', 'web'),

    /*
     | The Eloquent user model to provision and authenticate.
     */
    'user_model' => env('THIJSSENSOFTWARE_ID_USER_MODEL', 'App\\Models\\User'),

    /*
     | Where to send the user after a successful sign-in (fallback for
     | redirect()->intended()).
     */
    'home' => env('THIJSSENSOFTWARE_ID_HOME', '/dashboard'),

    /*
     | Shared secret for back-channel single logout. Thijssensoftware ID signs
     | its "this user signed out" call with it; without it that endpoint refuses
     | every call rather than trusting an unsigned one. Printed by `id:app`.
     */
    'logout_secret' => env('THIJSSENSOFTWARE_ID_LOGOUT_SECRET'),

    /*
     | Just-in-time provisioning. When true, a user who authenticates at the
     | IdP (and is authorised for this app) but has no local account yet is
     | created automatically. The IdP already enforces per-app access, so a
     | successful userinfo response means the user is allowed here.
     */
    'provision' => env('THIJSSENSOFTWARE_ID_PROVISION', true),
];
