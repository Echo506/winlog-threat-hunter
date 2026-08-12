namespace WinlogThreatHunter.EventCollector;

/// <summary>
/// Modelo normalizado para un evento de seguridad de Windows,
/// independiente del canal de origen (Security, System, etc.).
/// </summary>
public sealed class SecurityEvent
{
    public int EventId { get; init; }
    public string Channel { get; init; } = "Security";
    public string Provider { get; init; } = string.Empty;
    public DateTime TimeCreated { get; init; }
    public string? Computer { get; init; }
    public string? SubjectUserName { get; init; }
    public string? TargetUserName { get; init; }
    public string? IpAddress { get; init; }
    public string? ProcessName { get; init; }
    public string RawMessage { get; init; } = string.Empty;

    public override string ToString() =>
        $"[{TimeCreated:u}] EventId={EventId} Channel={Channel} User={SubjectUserName ?? TargetUserName} Computer={Computer}";
}
