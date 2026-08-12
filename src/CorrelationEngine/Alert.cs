using WinlogThreatHunter.EventCollector;

namespace WinlogThreatHunter.CorrelationEngine;

public enum AlertSeverity
{
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Alerta generada cuando una regla de correlación se dispara.
/// </summary>
public sealed class Alert
{
    public string RuleName { get; init; } = string.Empty;
    public string MitreTechniqueId { get; init; } = string.Empty;
    public string MitreTechniqueName { get; init; } = string.Empty;
    public AlertSeverity Severity { get; init; } = AlertSeverity.Medium;
    public DateTime TriggeredAt { get; init; } = DateTime.UtcNow;
    public string Description { get; init; } = string.Empty;
    public IReadOnlyList<SecurityEvent> RelatedEvents { get; init; } = Array.Empty<SecurityEvent>();

    public override string ToString() =>
        $"[{Severity}] {RuleName} ({MitreTechniqueId} - {MitreTechniqueName}) @ {TriggeredAt:u}: {Description}";
}
