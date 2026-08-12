using WinlogThreatHunter.EventCollector;

namespace WinlogThreatHunter.CorrelationEngine;

/// <summary>
/// Orquesta la ejecucion de todas las reglas de deteccion registradas
/// sobre un conjunto de eventos, devolviendo las alertas generadas.
/// </summary>
public sealed class AlertEngine
{
    private readonly List<IDetectionRule> _rules = new();

    public AlertEngine RegisterRule(IDetectionRule rule)
    {
        _rules.Add(rule);
        return this;
    }

    public IReadOnlyList<IDetectionRule> Rules => _rules;

    /// <summary>
    /// Ejecuta todas las reglas registradas contra el conjunto de eventos
    /// y devuelve las alertas ordenadas por severidad descendente.
    /// </summary>
    public IReadOnlyList<Alert> Run(IReadOnlyList<SecurityEvent> events)
    {
        var alerts = new List<Alert>();

        foreach (var rule in _rules)
        {
            alerts.AddRange(rule.Evaluate(events));
        }

        return alerts
            .OrderByDescending(a => a.Severity)
            .ThenByDescending(a => a.TriggeredAt)
            .ToList();
    }
}
