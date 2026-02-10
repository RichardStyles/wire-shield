# Wire Shield

A Laravel package that monitors Livewire update requests for deserialization attack patterns and other security threats. Built as a response to [CVE-2025-54068](https://github.com/livewire/livewire/security/advisories/GHSA-29cq-5w36-x7w3) and related gadget chain exploits.

## Installation

```bash
composer require richardstyles/wire-shield
```

The package auto-discovers and registers all middleware into the `web` middleware group. Zero configuration required.

To publish the config file:

```bash
php artisan vendor:publish --tag=wire-shield-config
```

## Requirements

- PHP 8.2+
- Laravel 11 or 12
- Livewire 3 or 4

## How It Works

The package registers a pipeline of three middleware that inspect every Livewire POST request (`X-Livewire` header) before it reaches Livewire's own handler. The core scanner performs a single pass over all components, with each scan type independently toggleable via config.

By default the package operates in **monitor mode** — threats are logged and events are dispatched, but requests are allowed through. Set `block_suspicious_requests` to `true` to reject malicious requests with a 403.

## Scanning Features

All scanning runs in the `ScanLivewirePayloads` middleware with a single iteration over components. Each feature can be toggled independently.

### Deserialization Detection

**Config:** `enabled` (default: `true`)

The core scanner. Inspects the `updates` and `calls` fields in each Livewire component payload for:

- **Known gadget classes** — Synthetic tuples (`[value, {"s": key, "class": "..."}]`) containing classes from the configurable `dangerous_classes` list. This is the exact CVE-2025-54068 attack pattern.
- **Unexpected classes** — Any synthetic tuple with a `class` key that isn't in the dangerous list is still flagged, since normal Livewire updates never contain class metadata.
- **Unknown synthesizer keys** — Synthetic tuples with unrecognised `s` values. Livewire has a fixed set of synthesizer abbreviations (`str`, `arr`, `mdl`, etc.). Unknown keys may indicate tampering.
- **Dangerous callables** — String values matching known dangerous PHP functions (`system`, `exec`, `passthru`, `eval`, etc.) via a precompiled regex pattern.
- **Suspicious property names** — Update property names that match known reconnaissance patterns observed in the wild as precursors to CVE exploitation. Examples include `areFormStateUpdateHooksDisabledForTesting`, `activeComponent`, and `cachedMountedTableAction` — internal Filament/Livewire properties that should never appear in legitimate update requests. Uses prefix matching so `activeComponent` also catches `activeComponentId`, etc.

### Snapshot Scanning

**Config:** `scan_snapshots` (default: `true`)

Decodes the JSON `snapshot` string in each component and scans the `data` field using the same detection logic as the core scanner. Provides defence-in-depth against scenarios where an attacker has a compromised `APP_KEY` and can forge valid checksums.

Also detects **malformed snapshots** — snapshot fields that contain invalid JSON.

### Call Method Validation

**Config:** `scan_call_methods` (default: `true`)

Validates method names in `components[].calls[].method` against a configurable `dangerous_methods` list. Flags:

- **PHP magic methods** — `__construct`, `__destruct`, `__wakeup`, `__sleep`, `__serialize`, `__unserialize`, `__toString`, `__invoke`, `__clone`, `__debugInfo`, `__set_state`
- **Livewire lifecycle hooks** — `mount`, `boot`, `hydrate`, `dehydrate`, `render`, `updating`, `updated`, `booted`

These methods should never be invoked directly via the wire protocol. Their presence in a call indicates probing or exploitation attempts.

### Memo Children Monitoring

**Config:** `scan_memo_children` (default: `false`)

Livewire excludes `memo.children` from its HMAC checksum calculation, meaning an attacker can tamper with child component IDs without triggering a checksum failure. Inspects children for:

- **Suspiciously long IDs** — Child IDs exceeding 40 characters
- **Namespace separators** — IDs containing backslashes (`\`), suggesting injected class references
- **Excessive count** — More children than the configurable `max_children_count` threshold

Disabled by default as it is a more aggressive check.

## Middleware

### ValidateLivewirePayloadSize

**Config:** `enforce_payload_size` (default: `false`)

Livewire's built-in `max_size` check uses the `Content-Length` header, which can be spoofed with chunked transfer encoding. This middleware measures the actual request body size via `strlen($request->getContent())` and rejects payloads exceeding `max_payload_bytes` (default: 1MB) with a 413 response.

Disabled by default since Livewire already has its own size check.

### ScanLivewirePayloads

**Config:** `enabled` (default: `true`)

The consolidated scanner that performs a single pass over all Livewire components. Runs all scanning features described above (deserialization detection, snapshot scanning, call method validation, memo children monitoring) in one loop. Snapshot JSON is decoded once per component regardless of how many snapshot-based features are enabled.

### ThrottleSuspiciousRequests

**Config:** `throttle_offenders` (default: `false`)

Tracks IPs that trigger threats using Laravel's `RateLimiter` and escalates responses:

| Strikes | Level | Response |
|---------|-------|----------|
| 1-2 | `warning` | Log only (default behaviour from other middleware) |
| 3-5 | `throttle` | 429 Too Many Requests with `Retry-After` header |
| 6+ | `block` | 403 Forbidden for the decay period |

Strike counts decay after `offender_decay_minutes` (default: 60 minutes). Thresholds are configurable via `offender_thresholds`.

Disabled by default. Enable for active defence against scanning tools like LivePyre.

## Events

### LivewireDeserializationAttempt

Dispatched once per request when any scan detects threats. Contains the consolidated list of all threats found.

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `ipAddress` | `string` | Client IP address |
| `userAgent` | `string` | Truncated user agent string |
| `requestPath` | `string` | Request path |
| `threats` | `array` | Array of threat details (type, severity, path, detail) |
| `timestamp` | `string` | ISO 8601 timestamp |

Attach listeners for Slack notifications, Sentry alerts, SIEM integration, etc.

### RepeatOffenderDetected

Dispatched when an IP crosses an escalation threshold (warning, throttle, or block).

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `ipAddress` | `string` | Offending IP address |
| `strikeCount` | `int` | Current strike count |
| `escalationLevel` | `string` | `warning`, `throttle`, or `block` |
| `timestamp` | `string` | ISO 8601 timestamp |

## Configuration

All features are toggleable. Key config options:

```php
return [
    'enabled' => true,                          // Master switch
    'block_suspicious_requests' => false,        // 403 on detection
    'log_channel' => null,                       // Dedicated log channel
    'scan_snapshots' => true,                    // Snapshot data scanning
    'scan_call_methods' => true,                 // Call method validation
    'scan_memo_children' => false,               // Memo children checking
    'throttle_offenders' => false,               // IP-based throttling
    'enforce_payload_size' => false,             // Body size enforcement
    'max_payload_bytes' => 1048576,              // 1MB
    'flag_unknown_synthesizer_keys' => true,     // Flag unknown synth keys
    'dispatch_events' => true,                   // Event dispatching
    'dangerous_classes' => [...],                // 21 known gadget chains
    'dangerous_callables' => [...],              // 20 dangerous functions
    'dangerous_methods' => [...],                // Magic + lifecycle methods
    'suspicious_update_properties' => [...],     // Recon probe property names
    'known_synthesizer_keys' => [...],           // Livewire's synth keys
    'offender_decay_minutes' => 60,              // Strike decay period
    'offender_thresholds' => [                   // Escalation thresholds
        'warning' => 1, 'throttle' => 3, 'block' => 6,
    ],
    'max_scan_depth' => 15,                      // Recursion limit
    'max_children_count' => 50,                  // Children count limit
];
```

## Threat Types

| Type | Severity | Scanner |
|------|----------|---------|
| `known_gadget_class` | critical | Deserialization / Snapshot |
| `unexpected_class_in_update` | critical | Deserialization / Snapshot |
| `unknown_synthesizer_key` | high | Deserialization / Snapshot |
| `dangerous_callable` | medium | Deserialization / Snapshot |
| `suspicious_property_update` | high | Deserialization |
| `malformed_snapshot` | high | Snapshot |
| `dangerous_method_call` | high | Call method |
| `suspicious_child_id` | high/critical | Memo children |
| `excessive_children_count` | medium | Memo children |

## Architecture

Internally, threats are represented as typed `Threat` data objects rather than raw arrays:

```php
use RichardStyles\WireShield\Data\Threat;
use RichardStyles\WireShield\Enums\ThreatSeverity;

// Created by scanners
new Threat(
    type: 'known_gadget_class',
    severity: ThreatSeverity::Critical,
    componentIndex: 0,
    path: 'components.0.updates.data.name',
    detail: 'Known gadget chain class: GuzzleHttp\Psr7\FnStream',
);
```

`ThreatSeverity` is a backed string enum with three cases: `Critical`, `High`, and `Medium`. The `Threat` DTO is a `final readonly` class with a `toArray()` method used at the serialisation boundary — events and log context always receive plain arrays for external consumers.

### Middleware Pipeline

The ServiceProvider registers three middleware in this order:

1. `ValidateLivewirePayloadSize` — Cheapest rejection (body size check)
2. `ScanLivewirePayloads` — Consolidated scanner (single pass over all components)
3. `ThrottleSuspiciousRequests` — Reads accumulated threats, must run last

### Performance

The consolidated scanner is optimised for minimal overhead on legitimate requests:

- **Single component iteration** — all scan types run in one loop
- **Snapshot decoded once** — shared between snapshot scanning and memo children monitoring
- **O(1) lookups** — dangerous classes, synthesizer keys, and method names use hash maps via `array_flip`
- **Precompiled regex** — dangerous callable detection uses a single `preg_match` instead of iterating
- **Lazy config caching** — config values and maps are resolved once per request

## Testing & Quality

```bash
# Run tests (83 tests)
vendor/bin/pest

# Static analysis (level 8)
vendor/bin/phpstan analyse

# Code formatting
vendor/bin/pint
```

All source files use `declare(strict_types=1)`. PHPStan is configured at level 8 with Larastan.

## License

MIT
