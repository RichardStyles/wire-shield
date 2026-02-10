<?php

declare(strict_types=1);

use RichardStyles\WireShield\Tests\TestCase;

pest()->extend(TestCase::class)->in('Feature');

/**
 * Build a fake Livewire snapshot JSON string.
 */
function fakeSnapshot(array $data = [], array $memoOverrides = []): string
{
    return json_encode([
        'data' => $data,
        'memo' => array_merge(['id' => 'test-component-id'], $memoOverrides),
        'checksum' => 'fake',
    ]);
}

/**
 * Build a Livewire update request payload with a single component.
 */
function livewirePayload(
    ?string $snapshot = null,
    array $updates = [],
    array $calls = [],
): array {
    return [
        'components' => [
            [
                'snapshot' => $snapshot ?? fakeSnapshot(),
                'updates' => $updates,
                'calls' => $calls,
            ],
        ],
    ];
}
