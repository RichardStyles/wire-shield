<?php

declare(strict_types=1);

namespace RichardStyles\WireShield\Enums;

enum ThreatSeverity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
}
