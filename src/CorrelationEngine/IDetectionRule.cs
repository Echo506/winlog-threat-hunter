using WinlogThreatHunter.EventCollector;

namespace WinlogThreatHunter.CorrelationEngine;

/// <summary>
/// Contrato para una regla de detección que analiza un conjunto de eventos
/// y produce cero o más alertas.
/// </summary>
public interface IDetectionRule
{
    string Name { get; }
    string MitreTechniqueId { get; }
    string MitreTechniqueName { get; }
    AlertSeverity Severity { get; }

    IEnumerable<Alert> Evaluate(IReadOnlyList<SecurityEvent> events);
}
