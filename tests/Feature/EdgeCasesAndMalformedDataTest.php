<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RichardStyles\WireShield\Events\LivewireDeserializationAttempt;

test('handles non-string snapshot gracefully', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    // When snapshot is not a string, decodeSnapshot should return nulls
    $this->postJson($this->updatePath, [
        'components' => [
            [
                'snapshot' => 12345, // Non-string snapshot
                'updates' => [],
                'calls' => [],
            ],
        ],
    ], ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('handles non-array component gracefully', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    // When component is not an array, should skip it
    $this->postJson($this->updatePath, [
        'components' => [
            'not-an-array', // Invalid component
            [
                'snapshot' => fakeSnapshot(),
                'updates' => [],
                'calls' => [],
            ],
        ],
    ], ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('handles non-array updates gracefully', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, [
        'components' => [
            [
                'snapshot' => fakeSnapshot(),
                'updates' => 'not-an-array', // Invalid updates
                'calls' => [],
            ],
        ],
    ], ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('handles non-array calls gracefully', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, [
        'components' => [
            [
                'snapshot' => fakeSnapshot(),
                'updates' => [],
                'calls' => 'not-an-array', // Invalid calls
            ],
        ],
    ], ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('handles non-array call items gracefully', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, [
        'components' => [
            [
                'snapshot' => fakeSnapshot(),
                'updates' => [],
                'calls' => [
                    'not-an-array', // Invalid call item
                    ['method' => 'save', 'params' => []],
                ],
            ],
        ],
    ], ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('handles deeply nested arrays within scan depth limit', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    // Create a deeply nested structure but within the default max_scan_depth (15)
    $nested = 'value';
    for ($i = 0; $i < 10; $i++) {
        $nested = [$nested];
    }

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['data' => $nested],
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('stops scanning when max depth is exceeded', function () {
    // Set a very low max depth
    config(['wire-shield.max_scan_depth' => 2]);
    Event::fake([LivewireDeserializationAttempt::class]);

    // Create a structure deeper than max depth
    $nested = ['evil', ['s' => 'str', 'class' => 'GuzzleHttp\\Psr7\\FnStream']];
    for ($i = 0; $i < 5; $i++) {
        $nested = [$nested];
    }

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['data' => $nested],
    ), ['X-Livewire' => '1']);

    // Should not detect the deeply nested threat due to depth limit
    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('handles empty dangerous callables config', function () {
    config(['wire-shield.dangerous_callables' => []]);
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        updates: ['command' => 'system'],
    ), ['X-Livewire' => '1']);

    // Should not detect any dangerous callables when config is empty
    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('scans regular nested arrays without synthetic tuples', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    // Regular nested array structure (not a synthetic tuple)
    $this->postJson($this->updatePath, livewirePayload(
        updates: [
            'data' => [
                'users' => [
                    ['name' => 'John', 'email' => 'john@example.com'],
                    ['name' => 'Jane', 'email' => 'jane@example.com'],
                ],
                'settings' => [
                    'theme' => 'dark',
                    'notifications' => true,
                ],
            ],
        ],
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('handles null snapshot in snapshot scanning', function () {
    Event::fake([LivewireDeserializationAttempt::class]);
    config(['wire-shield.scan_snapshots' => true]);

    $this->postJson($this->updatePath, [
        'components' => [
            [
                // No snapshot provided
                'updates' => [],
                'calls' => [],
            ],
        ],
    ], ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('handles null snapshot in memo children scanning', function () {
    Event::fake([LivewireDeserializationAttempt::class]);
    config(['wire-shield.scan_memo_children' => true]);

    $this->postJson($this->updatePath, [
        'components' => [
            [
                // No snapshot provided
                'updates' => [],
                'calls' => [],
            ],
        ],
    ], ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('handles non-array memo children gracefully', function () {
    Event::fake([LivewireDeserializationAttempt::class]);
    config(['wire-shield.scan_memo_children' => true]);

    $this->postJson($this->updatePath, [
        'components' => [
            [
                'snapshot' => json_encode([
                    'data' => [],
                    'memo' => [
                        'id' => 'test',
                        'children' => 'not-an-array', // Invalid children
                    ],
                    'checksum' => 'fake',
                ]),
                'updates' => [],
                'calls' => [],
            ],
        ],
    ], ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('handles non-string and non-array child ID gracefully', function () {
    Event::fake([LivewireDeserializationAttempt::class]);
    config(['wire-shield.scan_memo_children' => true]);

    $this->postJson($this->updatePath, [
        'components' => [
            [
                'snapshot' => fakeSnapshot([], [
                    'children' => [
                        'child1' => 12345, // Not a string or array
                        'child2' => 'valid-child-id',
                    ],
                ]),
                'updates' => [],
                'calls' => [],
            ],
        ],
    ], ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('handles child ID as array with non-string id field', function () {
    Event::fake([LivewireDeserializationAttempt::class]);
    config(['wire-shield.scan_memo_children' => true]);

    $this->postJson($this->updatePath, [
        'components' => [
            [
                'snapshot' => fakeSnapshot([], [
                    'children' => [
                        'child1' => ['id' => 12345], // id is not a string
                        'child2' => ['id' => 'valid-id'],
                    ],
                ]),
                'updates' => [],
                'calls' => [],
            ],
        ],
    ], ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});
