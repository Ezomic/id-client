<?php

declare(strict_types=1);

namespace Thijssensoftware\IdClient\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * ID revoked this user's access to the app. The package only ends the web
 * session; anything else the app issued, such as API tokens, is the app's to
 * revoke from a listener.
 */
final class AccessRevoked
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(public Model $user) {}
}
