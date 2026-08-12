using WinlogThreatHunter.EventCollector;

namespace WinlogThreatHunter.CorrelationEngine.Rules;

/// <summary>
/// Detecta intentos de fuerza bruta: multiples fallos de autenticacion (EventId 4625)
/// desde el mismo origen en una ventana de tiempo corta.
/// Mapea a MITRE ATT&CK T1110 (Brute Force).
/// </summary>
public sealed class BruteForceRule : IDetectionRule
{
    private readonly int _threshold;
    private readonly TimeSpan _window;

    public string Name => "Multiples fallos de autenticacion";
    public string MitreTechniqueId => "T1110";
    public string MitreTechniqueName => "Brute Force";
    public AlertSeverity Severity => AlertSeverity.High;

    public BruteForceRule(int threshold = 5, TimeSpan? window = null)
    {
        _threshold = threshold;
        _window = window ?? TimeSpan.FromMinutes(2);
    }

    public IEnumerable<Alert> Evaluate(IReadOnlyList<SecurityEvent> events)
    {
        var failedLogons = events
            .Where(e => e.EventId == 4625)
            .OrderBy(e => e.TimeCreated)
            .ToList();

        var groupedByTarget = failedLogons.GroupBy(e => e.TargetUserName ?? e.IpAddress ?? "unknown");

        foreach (var group in groupedByTarget)
        {
            var ordered = group.OrderBy(e => e.TimeCreated).ToList();

            for (int i = 0; i <= ordered.Count - _threshold; i++)
            {
                var windowEvents = ordered.Skip(i).Take(_threshold).ToList();
                var span = windowEvents[^1].TimeCreated - windowEvents[0].TimeCreated;

                if (span <= _window)
                {
                    yield return new Alert
                    {
                        RuleName = Name,
                        MitreTechniqueId = MitreTechniqueId,
                        MitreTechniqueName = MitreTechniqueName,
                        Severity = Severity,
                        Description = $"{_threshold} fallos de autenticacion contra '{group.Key}' en {span.TotalSeconds:N0}s",
                        RelatedEvents = windowEvents
                    };

                    // Evita generar alertas duplicadas para la misma ventana ya reportada.
                    i += _threshold - 1;
                }
            }
        }
    }
}
