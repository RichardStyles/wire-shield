<?php

declare(strict_types=1);

namespace RichardStyles\WireShield\Concerns;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use RichardStyles\WireShield\Data\Threat;
use RichardStyles\WireShield\Enums\ThreatSeverity;
use RichardStyles\WireShield\Enums\ThreatType;
use RichardStyles\WireShield\Events\LivewireDeserializationAttempt;
use Symfony\Component\HttpFoundation\Response;

trait ScansPayloads
{
    /** @var array<string, int>|null */
    private ?array $dangerousClassesMap = null;

    /** @var array<string, int>|null */
    private ?array $knownKeysMap = null;

    private ?string $dangerousCallablesPattern = null;

    private ?int $cachedMaxScanDepth = null;

    private ?bool $cachedFlagUnknownSynthesizerKeys = null;

    protected function isLivewireRequest(Request $request): bool
    {
        if (! $request->isMethod('POST')) {
            return false;
        }

        if ($request->hasHeader('X-Livewire')) {
            return true;
        }

        // Also match by route name — an attacker can omit the X-Livewire
        // header and Livewire will still process the update request.
        $route = $request->route();

        return $route && $route->named('*livewire.update');
    }

    /**
     * @return list<mixed>
     */
    protected function getLivewireComponents(Request $request): array
    {
        $components = $request->input('components', []);

        return is_array($components) ? array_values($components) : [];
    }

    /**
     * @param  array<string, mixed>  $component
     * @return array{snapshot: array<string, mixed>|null, raw: string|null}
     */
    protected function decodeSnapshot(array $component): array
    {
        $snapshotJson = $component['snapshot'] ?? null;

        if (! is_string($snapshotJson)) {
            return ['snapshot' => null, 'raw' => null];
        }

        $decoded = json_decode($snapshotJson, true);

        return [
            'snapshot' => is_array($decoded) ? $decoded : null,
            'raw' => $snapshotJson,
        ];
    }

    /**
     * @param  list<Threat>  $threats
     */
    protected function handleThreats(Request $request, array $threats, \Closure $next): Response
    {
        if (empty($threats)) {
            return $next($request);
        }

        $this->reportThreats($request, $threats);

        if (config('wire-shield.block_suspicious_requests', false)) {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        return $next($request);
    }

    /**
     * @return list<Threat>
     */
    protected function scanValue(mixed $value, string $path, int $componentIndex, int $depth = 0): array
    {
        if ($depth > $this->getMaxScanDepth()) {
            return [];
        }

        $threats = [];

        if (! is_array($value)) {
            if (is_string($value)) {
                array_push($threats, ...$this->checkDangerousCallables($value, $path, $componentIndex));
            }

            return $threats;
        }

        // Check for synthetic tuple pattern: [value, {"s": key}]
        // This mirrors Livewire's BaseUtils::isSyntheticTuple()
        if (count($value) === 2 && isset($value[1]['s'])) {
            $meta = $value[1];

            // Any synthetic tuple with a 'class' key in the updates field is
            // the exact CVE-2025-54068 attack pattern
            if (isset($meta['class'])) {
                $class = $meta['class'];

                if (isset($this->getDangerousClassesMap()[$class])) {
                    $threats[] = new Threat(
                        type: ThreatType::KnownGadgetClass,
                        severity: ThreatSeverity::Critical,
                        componentIndex: $componentIndex,
                        path: $path,
                        detail: "Known gadget chain class: {$class}",
                    );
                } else {
                    $threats[] = new Threat(
                        type: ThreatType::UnexpectedClassInUpdate,
                        severity: ThreatSeverity::Critical,
                        componentIndex: $componentIndex,
                        path: $path,
                        detail: "Unexpected class in update synthetic tuple: {$class}",
                    );
                }
            }

            // Check for unknown synthesizer keys
            if ($this->shouldFlagUnknownSynthesizerKeys()) {
                if (! isset($this->getKnownKeysMap()[$meta['s']])) {
                    $threats[] = new Threat(
                        type: ThreatType::UnknownSynthesizerKey,
                        severity: ThreatSeverity::High,
                        componentIndex: $componentIndex,
                        path: $path,
                        detail: "Unknown synthesizer key: {$meta['s']}",
                    );
                }
            }

            // Recurse into the data portion (first element of the tuple)
            array_push($threats, ...$this->scanValue($value[0], $path.'.0', $componentIndex, $depth + 1));

            return $threats;
        }

        // Regular array — recurse into all elements
        foreach ($value as $key => $child) {
            array_push($threats, ...$this->scanValue($child, $path.'.'.$key, $componentIndex, $depth + 1));
        }

        return $threats;
    }

    /**
     * @return list<Threat>
     */
    protected function checkSuspiciousPropertyName(string $property, string $path, int $componentIndex): array
    {
        $threats = [];

        /** @var list<string> $suspiciousProperties */
        $suspiciousProperties = config('wire-shield.suspicious_update_properties', []);

        foreach ($suspiciousProperties as $pattern) {
            if ($property === $pattern || str_starts_with($property, $pattern)) {
                $threats[] = new Threat(
                    type: ThreatType::SuspiciousPropertyUpdate,
                    severity: ThreatSeverity::High,
                    componentIndex: $componentIndex,
                    path: $path,
                    detail: "Suspicious property update: {$property} (matches pattern: {$pattern})",
                );

                break;
            }
        }

        return $threats;
    }

    /**
     * @return list<Threat>
     */
    protected function checkDangerousCallables(string $value, string $path, int $componentIndex): array
    {
        $threats = [];
        $pattern = $this->getDangerousCallablesPattern();

        if ($pattern === '') {
            return $threats;
        }

        if (preg_match($pattern, $value, $matches) === 1) {
            $threats[] = new Threat(
                type: ThreatType::DangerousCallable,
                severity: ThreatSeverity::Medium,
                componentIndex: $componentIndex,
                path: $path,
                detail: "Dangerous callable reference: {$matches[0]}",
            );
        }

        return $threats;
    }

    /**
     * @param  list<Threat>  $threats
     */
    protected function reportThreats(Request $request, array $threats): void
    {
        // Store threats on the request for downstream middleware (e.g. ThrottleSuspiciousRequests)
        /** @var list<Threat> $existing */
        $existing = $request->attributes->get('wire_shield_threats', []);
        array_push($existing, ...$threats);
        $request->attributes->set('wire_shield_threats', $existing);

        $threatArrays = array_map(fn (Threat $threat) => [
            ...$threat->toArray(),
            'detail' => Str::limit($threat->detail, 500),
        ], $threats);

        // Built-in logging — optional, users can handle via event listeners instead
        if (config('wire-shield.log_threats', true)) {
            $channel = config('wire-shield.log_channel');
            $logger = $channel ? Log::channel($channel) : Log::getFacadeRoot();

            $hasCritical = false;

            foreach ($threats as $threat) {
                if ($threat->severity === ThreatSeverity::Critical) {
                    $hasCritical = true;

                    break;
                }
            }

            $context = [
                'ip' => $request->ip(),
                'user_agent' => Str::limit($request->userAgent() ?? '', 200),
                'path' => $request->path(),
                'threat_count' => count($threats),
                'threats' => $threatArrays,
            ];

            if ($hasCritical) {
                $logger->critical('Livewire deserialization attack pattern detected', $context);
            } else {
                $logger->warning('Suspicious Livewire request detected', $context);
            }
        }

        // Dispatch event for custom handling
        if (config('wire-shield.dispatch_events', true)) {
            LivewireDeserializationAttempt::dispatch(
                (string) $request->ip(),
                Str::limit($request->userAgent() ?? '', 200),
                $request->path(),
                $threatArrays,
                now()->toIso8601String(),
            );
        }
    }

    /**
     * @return array<string, int>
     */
    private function getDangerousClassesMap(): array
    {
        if ($this->dangerousClassesMap === null) {
            /** @var list<string> $classes */
            $classes = config('wire-shield.dangerous_classes', []);
            $this->dangerousClassesMap = array_flip($classes);
        }

        return $this->dangerousClassesMap;
    }

    /**
     * @return array<string, int>
     */
    private function getKnownKeysMap(): array
    {
        if ($this->knownKeysMap === null) {
            /** @var list<string> $keys */
            $keys = config('wire-shield.known_synthesizer_keys', []);
            $this->knownKeysMap = array_flip($keys);
        }

        return $this->knownKeysMap;
    }

    private function getDangerousCallablesPattern(): string
    {
        if ($this->dangerousCallablesPattern === null) {
            /** @var list<string> $callables */
            $callables = config('wire-shield.dangerous_callables', []);

            if ($callables === []) {
                $this->dangerousCallablesPattern = '';

                return '';
            }

            $escaped = array_map(
                static fn (string $c): string => preg_quote($c, '/'),
                $callables
            );

            $this->dangerousCallablesPattern = '/'.implode('|', $escaped).'/i';
        }

        return $this->dangerousCallablesPattern;
    }

    private function getMaxScanDepth(): int
    {
        if ($this->cachedMaxScanDepth === null) {
            $this->cachedMaxScanDepth = (int) config('wire-shield.max_scan_depth', 15);
        }

        return $this->cachedMaxScanDepth;
    }

    private function shouldFlagUnknownSynthesizerKeys(): bool
    {
        if ($this->cachedFlagUnknownSynthesizerKeys === null) {
            $this->cachedFlagUnknownSynthesizerKeys = (bool) config('wire-shield.flag_unknown_synthesizer_keys', true);
        }

        return $this->cachedFlagUnknownSynthesizerKeys;
    }
}
