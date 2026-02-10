<?php

declare(strict_types=1);

namespace RichardStyles\WireShield\Data;

use RichardStyles\WireShield\Enums\ThreatSeverity;

final readonly class Threat
{
    public function __construct(
        public string $type,
        public ThreatSeverity $severity,
        public int $componentIndex,
        public string $path,
        public string $detail,
    ) {}

    /**
     * @return array{type: string, severity: string, component_index: int, path: string, detail: string}
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'severity' => $this->severity->value,
            'component_index' => $this->componentIndex,
            'path' => $this->path,
            'detail' => $this->detail,
        ];
    }
}
