using WinlogThreatHunter.EventCollector;

namespace WinlogThreatHunter.CorrelationEngine.Rules;

/// <summary>
/// Detecta creacion de una cuenta (EventId 4720) seguida de su asignacion
/// a un grupo privilegiado (EventId 4732) en una ventana de tiempo corta.
/// Mapea a MITRE ATT&CK T1098 (Account Manipulation).
/// </summary>
public sealed class PrivilegeEscalationRule : IDetectionRule
{
    private readonly TimeSpan _window;

    public string Name => "Creacion de cuenta con escalamiento de privilegios";
    public string MitreTechniqueId => "T1098";
    public string MitreTechniqueName => "Account Manipulation";
    public AlertSeverity Severity => AlertSeverity.Critical;

    public PrivilegeEscalationRule(TimeSpan? window = null)
    {
        _window = window ?? TimeSpan.FromMinutes(10);
    }

    public IEnumerable<Alert> Evaluate(IReadOnlyList<SecurityEvent> events)
    {
        var accountCreations = events.Where(e => e.EventId == 4720).ToList();
        var groupAdditions = events.Where(e => e.EventId == 4732).ToList();

        foreach (var creation in accountCreations)
        {
            var matchingAddition = groupAdditions.FirstOrDefault(g =>
                string.Equals(g.TargetUserName, creation.TargetUserName, StringComparison.OrdinalIgnoreCase) &&
                g.TimeCreated >= creation.TimeCreated &&
                g.TimeCreated - creation.TimeCreated <= _window);

            if (matchingAddition is not null)
            {
                yield return new Alert
                {
                    RuleName = Name,
                    MitreTechniqueId = MitreTechniqueId,
                    MitreTechniqueName = MitreTechniqueName,
                    Severity = Severity,
                    Description = $"Cuenta '{creation.TargetUserName}' creada y agregada a grupo privilegiado en {(matchingAddition.TimeCreated - creation.TimeCreated).TotalMinutes:N1} min",
                    RelatedEvents = new[] { creation, matchingAddition }
                };
            }
        }
    }
}
