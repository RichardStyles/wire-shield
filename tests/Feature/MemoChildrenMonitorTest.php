<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RichardStyles\WireShield\Events\LivewireDeserializationAttempt;

beforeEach(function () {
    config(['wire-shield.scan_memo_children' => true]);
});

test('normal children pass through', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot([], ['children' => ['child1' => 'abc123def456', 'child2' => 'xyz789ghi012']]),
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});

test('detects suspiciously long child ID', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot([], ['children' => ['child1' => str_repeat('a', 50)]]),
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'suspicious_child_id');
    });
});

test('detects namespace separator in child ID', function () {
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot([], ['children' => ['child1' => 'GuzzleHttp\\Psr7\\FnStream']]),
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains(function ($threat) {
            return $threat['type'] === 'suspicious_child_id'
                && str_contains($threat['detail'], 'namespace separator');
        });
    });
});

test('detects excessive children count', function () {
    Event::fake([LivewireDeserializationAttempt::class]);
    config(['wire-shield.max_children_count' => 3]);

    $children = [];
    for ($i = 0; $i < 5; $i++) {
        $children["child{$i}"] = "id{$i}";
    }

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot([], ['children' => $children]),
    ), ['X-Livewire' => '1']);

    Event::assertDispatched(LivewireDeserializationAttempt::class, function ($event) {
        return collect($event->threats)->contains('type', 'excessive_children_count');
    });
});

test('disabled scan_memo_children skips scanning', function () {
    config(['wire-shield.scan_memo_children' => false]);
    Event::fake([LivewireDeserializationAttempt::class]);

    $this->postJson($this->updatePath, livewirePayload(
        snapshot: fakeSnapshot([], ['children' => ['child1' => 'GuzzleHttp\\Psr7\\FnStream']]),
    ), ['X-Livewire' => '1']);

    Event::assertNotDispatched(LivewireDeserializationAttempt::class);
});
