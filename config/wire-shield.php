<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Enable Monitoring
    |--------------------------------------------------------------------------
    |
    | Toggle the deserialization attack monitor on or off.
    |
    */

    'enabled' => env('WIRE_SHIELD_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Block Suspicious Requests
    |--------------------------------------------------------------------------
    |
    | When enabled, requests matching attack patterns will be rejected with
    | a 403 response. Off by default since the patched Livewire version
    | already prevents exploitation — this middleware provides visibility.
    |
    */

    'block_suspicious_requests' => env('WIRE_SHIELD_BLOCK', false),

    /*
    |--------------------------------------------------------------------------
    | Log Threats
    |--------------------------------------------------------------------------
    |
    | Enable built-in logging of threats. When disabled, no automatic logging
    | occurs — listen to the LivewireDeserializationAttempt event instead to
    | handle logging, alerting, or integration with your monitoring system.
    |
    */

    'log_threats' => env('WIRE_SHIELD_LOG_THREATS', true),

    /*
    |--------------------------------------------------------------------------
    | Log Channel
    |--------------------------------------------------------------------------
    |
    | The log channel to write security alerts to. Set to null to use the
    | default channel. Consider a dedicated 'security' channel for easier
    | filtering and longer retention. Only used when log_threats is enabled.
    |
    */

    'log_channel' => env('WIRE_SHIELD_LOG_CHANNEL', null),

    /*
    |--------------------------------------------------------------------------
    | Dangerous Classes
    |--------------------------------------------------------------------------
    |
    | Known PHP gadget chain classes used in deserialization attacks.
    | These complement Livewire's built-in SecurityPolicy denylist which
    | does not cover all known gadget chains.
    |
    */

    'dangerous_classes' => [
        'GuzzleHttp\\Psr7\\FnStream',
        'GuzzleHttp\\Psr7\\AppendStream',
        'League\\Flysystem\\UrlGeneration\\ShardedPrefixPublicUrlGenerator',
        'Laravel\\SerializableClosure\\Serializers\\Signed',
        'Illuminate\\Broadcasting\\BroadcastEvent',
        'Illuminate\\Broadcasting\\PendingBroadcast',
        'Illuminate\\Bus\\Queueable',
        'Illuminate\\Container\\Container',
        'Illuminate\\Database\\Capsule\\Manager',
        'Illuminate\\Filesystem\\Filesystem',
        'Illuminate\\Foundation\\Testing\\PendingCommand',
        'Illuminate\\Mail\\Mailer',
        'Illuminate\\Queue\\CallQueuedClosure',
        'Symfony\\Component\\Process\\Process',
        'Symfony\\Component\\Finder\\Finder',
        'Monolog\\Handler\\SyslogUdpHandler',
        'Monolog\\Handler\\NativeMailerHandler',
        'Faker\\Generator',
        'Carbon\\CarbonInterval',
        'PhpParser\\NodeTraverser',
        'Doctrine\\Instantiator\\Instantiator',
    ],

    /*
    |--------------------------------------------------------------------------
    | Dangerous Callables
    |--------------------------------------------------------------------------
    |
    | Function names that should never appear as string values within
    | Livewire update payloads. Presence suggests an exploitation attempt.
    |
    */

    'dangerous_callables' => [
        'system', 'exec', 'passthru', 'shell_exec',
        'proc_open', 'popen', 'eval', 'assert',
        'base64_decode', 'unserialize',
        'pcntl_exec', 'curl_exec',
        'file_get_contents', 'file_put_contents',
        'fopen', 'fwrite',
        'call_user_func', 'call_user_func_array',
        'create_function', 'preg_replace',
    ],

    /*
    |--------------------------------------------------------------------------
    | Known Synthesizer Keys
    |--------------------------------------------------------------------------
    |
    | Legitimate Livewire synthesizer keys. Any synthetic tuple with an
    | unknown key is flagged. Add keys from third-party packages here.
    |
    */

    'known_synthesizer_keys' => [
        'arr', 'cbn', 'clctn', 'str', 'enm', 'std',
        'int', 'float', 'fil', 'form', 'wrbl',
        'mdl', 'elcln', 'elmdl', 'elcl',
    ],

    /*
    |--------------------------------------------------------------------------
    | Flag Unknown Synthesizer Keys
    |--------------------------------------------------------------------------
    |
    | Whether to flag synthetic tuples with unrecognised synthesizer keys.
    | Disable if third-party packages register custom synthesizers that
    | you haven't added to the known list above.
    |
    */

    'flag_unknown_synthesizer_keys' => true,

    /*
    |--------------------------------------------------------------------------
    | Suspicious Update Properties
    |--------------------------------------------------------------------------
    |
    | Property names in Livewire update payloads that indicate reconnaissance
    | or exploitation attempts. These are internal framework properties that
    | should never appear in legitimate requests. Matched using prefix
    | matching — e.g. "activeComponent" catches "activeComponentId" too.
    |
    | Observed in the wild as precursors to CVE-2025-54068 exploitation:
    |   - areFormStateUpdateHooksDisabledForTesting (Filament internal)
    |   - activeComponent (Filament internal)
    |   - cachedMountedTableAction (Filament internal)
    |
    */

    'suspicious_update_properties' => [
        'areFormStateUpdateHooksDisabledForTesting',
        'activeComponent',
        'cachedMountedTableAction',
        'cachedMountedTableBulkAction',
        'cachedMountedTableActionRecord',
        'mountedActions',
        'mountedActionsArguments',
        'mountedActionsData',
    ],

    /*
    |--------------------------------------------------------------------------
    | Max Scan Depth
    |--------------------------------------------------------------------------
    |
    | Maximum recursion depth when scanning nested payload structures.
    | Prevents the scanner itself from being abused with deeply nested data.
    |
    */

    'max_scan_depth' => 15,

    /*
    |--------------------------------------------------------------------------
    | Dispatch Events
    |--------------------------------------------------------------------------
    |
    | When enabled, a LivewireDeserializationAttempt event is dispatched on
    | detection. Attach listeners for Slack, Sentry, SIEM integration, etc.
    |
    */

    'dispatch_events' => true,

    /*
    |--------------------------------------------------------------------------
    | Scan Snapshots
    |--------------------------------------------------------------------------
    |
    | Scan the decoded snapshot data for the same attack patterns checked in
    | updates. Provides defence-in-depth against compromised APP_KEY
    | scenarios where an attacker can forge valid checksums.
    |
    */

    'scan_snapshots' => env('WIRE_SHIELD_SCAN_SNAPSHOTS', true),

    /*
    |--------------------------------------------------------------------------
    | Scan Call Methods
    |--------------------------------------------------------------------------
    |
    | Check method names in Livewire calls for dangerous patterns like PHP
    | magic methods or Livewire lifecycle hooks that should never be called
    | directly via the wire protocol.
    |
    */

    'scan_call_methods' => env('WIRE_SHIELD_SCAN_CALLS', true),

    'dangerous_methods' => [
        '__construct', '__destruct', '__wakeup', '__sleep',
        '__serialize', '__unserialize', '__toString', '__invoke',
        '__clone', '__debugInfo', '__set_state',
        'mount', 'boot', 'hydrate', 'dehydrate', 'render',
        'updating', 'updated', 'booted',
    ],

    /*
    |--------------------------------------------------------------------------
    | Repeat Offender Tracking
    |--------------------------------------------------------------------------
    |
    | Track IPs that trigger threats and escalate responses. Uses Laravel's
    | cache to maintain strike counts. Off by default.
    |
    | Escalation levels:
    |   warning  — log only (default behaviour)
    |   throttle — return 429 with Retry-After header
    |   block    — return 403 for the decay period
    |
    */

    'throttle_offenders' => env('WIRE_SHIELD_THROTTLE', false),

    'offender_decay_minutes' => 60,

    'offender_thresholds' => [
        'warning' => 1,
        'throttle' => 3,
        'block' => 6,
    ],

    /*
    |--------------------------------------------------------------------------
    | Scan Memo Children
    |--------------------------------------------------------------------------
    |
    | Livewire excludes memo.children from its checksum calculation, making
    | it possible to tamper with child component IDs. This scanner flags
    | suspicious patterns in children. Off by default (paranoid mode).
    |
    */

    'scan_memo_children' => env('WIRE_SHIELD_SCAN_CHILDREN', false),

    'max_children_count' => 50,

    /*
    |--------------------------------------------------------------------------
    | Payload Size Enforcement
    |--------------------------------------------------------------------------
    |
    | Livewire's built-in max_size check uses Content-Length which can be
    | spoofed with chunked transfer encoding. This measures the actual
    | request body size. Off by default.
    |
    */

    'enforce_payload_size' => env('WIRE_SHIELD_ENFORCE_SIZE', false),

    'max_payload_bytes' => 1048576,

];
