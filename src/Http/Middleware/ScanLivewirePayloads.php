<?php

declare(strict_types=1);

namespace RichardStyles\WireShield\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use RichardStyles\WireShield\Concerns\ScansPayloads;
use RichardStyles\WireShield\Data\Threat;
use RichardStyles\WireShield\Enums\ThreatSeverity;
use Symfony\Component\HttpFoundation\Response;

class ScanLivewirePayloads
{
    use ScansPayloads;

    public function handle(Request $request, Closure $next): Response
    {
        if (! config('wire-shield.enabled', true) || ! $this->isLivewireRequest($request)) {
            return $next($request);
        }

        $scanCallMethods = (bool) config('wire-shield.scan_call_methods', true);
        $scanSnapshots = (bool) config('wire-shield.scan_snapshots', true);
        $scanMemoChildren = (bool) config('wire-shield.scan_memo_children', false);
        $needsSnapshot = $scanSnapshots || $scanMemoChildren;

        /** @var array<string, int> $dangerousMethods */
        $dangerousMethods = $scanCallMethods ? $this->buildDangerousMethodsMap() : [];

        $threats = [];

        foreach ($this->getLivewireComponents($request) as $index => $component) {
            if (! is_array($component)) {
                continue;
            }

            // Core deserialization detection — scan updates and call parameters
            array_push($threats, ...$this->scanUpdates($component, $index));
            array_push($threats, ...$this->scanCallParams($component, $index));

            // Call method name validation
            if ($scanCallMethods) {
                array_push($threats, ...$this->scanCallMethods($component, $index, $dangerousMethods));
            }

            // Snapshot-based scanning — decode once for both scanners
            if ($needsSnapshot) {
                ['snapshot' => $snapshot, 'raw' => $raw] = $this->decodeSnapshot($component);

                if ($scanSnapshots) {
                    array_push($threats, ...$this->scanSnapshotData($snapshot, $raw, $index));
                }

                if ($scanMemoChildren) {
                    array_push($threats, ...$this->scanMemoChildren($snapshot, $index));
                }
            }
        }

        return $this->handleThreats($request, $threats, $next);
    }

    /**
     * Scan update property values for synthetic tuples, dangerous classes, and callables.
     *
     * @param  array<string, mixed>  $component
     * @return list<Threat>
     */
    private function scanUpdates(array $component, int $index): array
    {
        $threats = [];
        $updates = $component['updates'] ?? [];

        if (! is_array($updates)) {
            return $threats;
        }

        foreach ($updates as $property => $value) {
            $path = "components.{$index}.updates.{$property}";

            array_push($threats, ...$this->checkSuspiciousPropertyName((string) $property, $path, $index));
            array_push($threats, ...$this->scanValue($value, $path, $index));
        }

        return $threats;
    }

    /**
     * Scan call parameter values for synthetic tuples and dangerous patterns.
     *
     * @param  array<string, mixed>  $component
     * @return list<Threat>
     */
    private function scanCallParams(array $component, int $index): array
    {
        $threats = [];
        $calls = $component['calls'] ?? [];

        if (! is_array($calls)) {
            return $threats;
        }

        foreach ($calls as $callIndex => $call) {
            if (! is_array($call)) {
                continue;
            }

            $params = $call['params'] ?? [];

            if (is_array($params)) {
                foreach ($params as $paramIndex => $param) {
                    array_push($threats, ...$this->scanValue(
                        $param,
                        "components.{$index}.calls.{$callIndex}.params.{$paramIndex}",
                        $index,
                    ));
                }
            }
        }

        return $threats;
    }

    /**
     * Validate call method names against the dangerous methods list.
     *
     * @param  array<string, mixed>  $component
     * @param  array<string, int>  $dangerousMethods
     * @return list<Threat>
     */
    private function scanCallMethods(array $component, int $index, array $dangerousMethods): array
    {
        $threats = [];
        $calls = $component['calls'] ?? [];

        if (! is_array($calls)) {
            return $threats;
        }

        foreach ($calls as $callIndex => $call) {
            if (! is_array($call)) {
                continue;
            }

            $method = $call['method'] ?? null;

            if (is_string($method) && isset($dangerousMethods[$method])) {
                $threats[] = new Threat(
                    type: 'dangerous_method_call',
                    severity: ThreatSeverity::High,
                    componentIndex: $index,
                    path: "components.{$index}.calls.{$callIndex}.method",
                    detail: "Dangerous method call: {$method}",
                );
            }
        }

        return $threats;
    }

    /**
     * Scan decoded snapshot data for attack patterns and malformed JSON.
     *
     * @param  array<string, mixed>|null  $snapshot
     * @return list<Threat>
     */
    private function scanSnapshotData(?array $snapshot, ?string $raw, int $index): array
    {
        $threats = [];

        if ($raw !== null && $snapshot === null) {
            $threats[] = new Threat(
                type: 'malformed_snapshot',
                severity: ThreatSeverity::High,
                componentIndex: $index,
                path: "components.{$index}.snapshot",
                detail: 'Snapshot contains invalid JSON',
            );

            return $threats;
        }

        if ($snapshot === null) {
            return $threats;
        }

        $data = $snapshot['data'] ?? [];

        if (is_array($data)) {
            foreach ($data as $property => $value) {
                array_push($threats, ...$this->scanValue($value, "components.{$index}.snapshot.data.{$property}", $index));
            }
        }

        return $threats;
    }

    /**
     * Check memo children for tampering indicators.
     *
     * @param  array<string, mixed>|null  $snapshot
     * @return list<Threat>
     */
    private function scanMemoChildren(?array $snapshot, int $index): array
    {
        if ($snapshot === null) {
            return [];
        }

        $threats = [];
        $children = $snapshot['memo']['children'] ?? [];

        if (! is_array($children)) {
            return $threats;
        }

        $maxChildren = (int) config('wire-shield.max_children_count', 50);

        if (count($children) > $maxChildren) {
            $threats[] = new Threat(
                type: 'excessive_children_count',
                severity: ThreatSeverity::Medium,
                componentIndex: $index,
                path: "components.{$index}.snapshot.memo.children",
                detail: 'Children count ('.count($children).") exceeds maximum ({$maxChildren})",
            );
        }

        foreach ($children as $childKey => $childId) {
            if (! is_string($childId) && ! is_array($childId)) {
                continue;
            }

            $idToCheck = is_array($childId) ? ($childId['id'] ?? '') : $childId;

            if (! is_string($idToCheck)) {
                continue;
            }

            if (strlen($idToCheck) > 40) {
                $threats[] = new Threat(
                    type: 'suspicious_child_id',
                    severity: ThreatSeverity::High,
                    componentIndex: $index,
                    path: "components.{$index}.snapshot.memo.children.{$childKey}",
                    detail: 'Child ID is suspiciously long ('.strlen($idToCheck).' chars)',
                );
            }

            if (str_contains($idToCheck, '\\')) {
                $threats[] = new Threat(
                    type: 'suspicious_child_id',
                    severity: ThreatSeverity::Critical,
                    componentIndex: $index,
                    path: "components.{$index}.snapshot.memo.children.{$childKey}",
                    detail: 'Child ID contains namespace separator pattern',
                );
            }
        }

        return $threats;
    }

    /**
     * @return array<string, int>
     */
    private function buildDangerousMethodsMap(): array
    {
        /** @var list<string> $methods */
        $methods = config('wire-shield.dangerous_methods', []);

        return array_flip($methods);
    }
}
