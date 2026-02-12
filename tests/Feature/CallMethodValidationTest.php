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
    config([
        'wire-shield.scan_call_methods' => false,
        'wire-shield.scan_magic_method_patterns' => false,
    ]);
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

test('detects suspicious magic method patterns', function (string $method) {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        calls: [['method' => $method, 'params' => []]],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'suspicious_magic_method_pattern');
    });
})->with([
    '__foobar',
    '__custom',
    '__probe',
    '__test123',
]);

test('disabled scan_magic_method_patterns config skips pattern scanning', function () {
    config(['wire-shield.scan_magic_method_patterns' => false]);
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        calls: [['method' => '__foobar', 'params' => []]],
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('magic method pattern detection respects exact dangerous methods list', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    // Known dangerous method should trigger dangerous_method_call, not pattern match
    $this->postJson($this->updatePath, livewirePayload(
        calls: [['method' => '__construct', 'params' => []]],
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        $threats = collect($event->threats);

        return $threats->contains('type', 'dangerous_method_call')
            && ! $threats->contains('type', 'suspicious_magic_method_pattern');
    });
});
