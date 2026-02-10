<?php

declare(strict_types=1);

namespace RichardStyles\WireShield\Events;

use Illuminate\Foundation\Events\Dispatchable;

class LivewireDeserializationAttempt
{
    use Dispatchable;

    /**
     * @param  list<array{type: string, severity: string, component_index: int, path: string, detail: string}>  $threats
     */
    public function __construct(
        public string $ipAddress,
        public string $userAgent,
        public string $requestPath,
        public array $threats,
        public string $timestamp,
    ) {}
}
