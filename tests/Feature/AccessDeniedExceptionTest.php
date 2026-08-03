<?php

declare(strict_types=1);

use Thijssensoftware\IdClient\Exceptions\AccessDeniedException;

it('is a runtime exception carrying the reason', function (): void {
    $exception = new AccessDeniedException('You do not have access to this application.');

    expect($exception)->toBeInstanceOf(RuntimeException::class)
        ->and($exception->getMessage())->toBe('You do not have access to this application.');
});
