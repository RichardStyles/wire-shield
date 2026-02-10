<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RichardStyles\WireShield\Events\LivewireDeserializationAttempt;

test('normal method calls pass through', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        calls: [
            ['method' => 'save', 'params' => []],
            ['method' => 'submit', 'params' => []],
            ['method' => 'delete', 'params' => []],
        ],
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('detects magic method calls', function (string $method) {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        calls: [['method' => $method, 'params' => []]],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'dangerous_method_call');
    });
})->with([
    '__construct', '__destruct', '__wakeup', '__sleep',
    '__serialize', '__unserialize', '__toString', '__invoke',
]);

test('detects lifecycle method calls', function (string $method) {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        calls: [['method' => $method, 'params' => []]],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'dangerous_method_call');
    });
})->with([
    'mount', 'boot', 'hydrate', 'dehydrate',
    'render', 'updating', 'updated', 'booted',
]);

test('disabled scan_call_methods config skips scanning', function () {
    config(['wire-shield.scan_call_methods' => false]);
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        calls: [['method' => '__destruct', 'params' => []]],
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('call method blocking mode returns 403', function () {
    config(['wire-shield.block_suspicious_requests' => true]);
    Event::fake([LivewireDeserializationAttempt::class]);

    $response = $this->postJson($this->updatePath, livewirePayload(
        calls: [['method' => '__destruct', 'params' => []]],
    ), ['X-Livewire' => '1']);

    $response->assertStatus(403);
});

test('detects dangerous method among normal calls', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        calls: [
            ['method' => 'save', 'params' => []],
            ['method' => '__wakeup', 'params' => []],
            ['method' => 'submit', 'params' => []],
        ],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'dangerous_method_call');
    });
});
