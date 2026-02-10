<?php

declare(strict_types=1);

namespace RichardStyles\WireShield\Events;

use Illuminate\Foundation\Events\Dispatchable;

class RepeatOffenderDetected
{
    use Dispatchable;

    public function __construct(
        public string $ipAddress,
        public int $strikeCount,
        public string $escalationLevel,
        public string $timestamp,
    ) {}
}
