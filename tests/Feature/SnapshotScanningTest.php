<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RichardStyles\WireShield\Events\LivewireDeserializationAttempt;

test('normal snapshot data passes through', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot(['name' => 'test', 'count' => 5]),
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('detects gadget class in snapshot data', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot([
            'name' => ['malicious_data', ['s' => 'str', 'class' => 'GuzzleHttp\\Psr7\\FnStream']],
        ]),
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'known_gadget_class');
    });
});

test('detects unexpected class in snapshot data', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot([
            'name' => ['data', ['s' => 'str', 'class' => 'Some\\Evil\\SnapshotClass']],
        ]),
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'unexpected_class_in_update');
    });
});

test('detects malformed snapshot json', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: '{not valid json!!!',
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'malformed_snapshot');
    });
});

test('disabled scan_snapshots config skips scanning', function () {
    config(['wire-shield.scan_snapshots' => false]);
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot([
            'name' => ['data', ['s' => 'str', 'class' => 'GuzzleHttp\\Psr7\\FnStream']],
        ]),
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('snapshot scanning blocking mode returns 403', function () {
    config(['wire-shield.block_suspicious_requests' => true]);
    Event::fake([LivewireDeserializationAttempt::class]);

    $response = $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot([
            'name' => ['payload', ['s' => 'str', 'class' => 'GuzzleHttp\\Psr7\\FnStream']],
        ]),
    ), ['X-Livewire' => '1']);

    $response->assertStatus(403);
});
