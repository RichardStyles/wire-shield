<?php

declare(strict_types=1);

namespace RichardStyles\WireShield\Enums;

enum ThreatType: string
{
    case KnownGadgetClass = 'known_gadget_class';
    case UnexpectedClassInUpdate = 'unexpected_class_in_update';
    case UnknownSynthesizerKey = 'unknown_synthesizer_key';
    case SuspiciousPropertyUpdate = 'suspicious_property_update';
    case DangerousCallable = 'dangerous_callable';
    case DangerousMethodCall = 'dangerous_method_call';
    case MalformedSnapshot = 'malformed_snapshot';
    case ExcessiveChildrenCount = 'excessive_children_count';
    case SuspiciousChildId = 'suspicious_child_id';
}
