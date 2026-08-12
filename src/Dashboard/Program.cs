using WinlogThreatHunter.AttackSimulator;
using WinlogThreatHunter.CorrelationEngine;
using WinlogThreatHunter.CorrelationEngine.Rules;

Console.WriteLine("==============================================");
Console.WriteLine("  WinLog Threat Hunter - SOC Dashboard (demo)");
Console.WriteLine("==============================================");
Console.WriteLine();

// 1. Generar telemetria sintetica (simulador de ataques)
var simulator = new ScenarioGenerator();
var events = simulator.GenerateMixedTraffic(benignCount: 25);

Console.WriteLine($"[+] {events.Count} eventos generados (trafico benigno + escenarios de ataque)");
Console.WriteLine();

// 2. Registrar reglas de deteccion en el motor de correlacion
var engine = new AlertEngine()
    .RegisterRule(new BruteForceRule())
    .RegisterRule(new PrivilegeEscalationRule());

Console.WriteLine($"[+] {engine.Rules.Count} reglas de deteccion activas:");
foreach (var rule in engine.Rules)
{
    Console.WriteLine($"    - {rule.Name} ({rule.MitreTechniqueId} - {rule.MitreTechniqueName})");
}
Console.WriteLine();

// 3. Ejecutar correlacion
var alerts = engine.Run(events);

// 4. Dashboard de alertas (consola)
Console.WriteLine($"[!] {alerts.Count} alertas generadas:");
Console.WriteLine(new string('-', 60));

foreach (var alert in alerts)
{
    var color = alert.Severity switch
    {
        AlertSeverity.Critical => ConsoleColor.Red,
        AlertSeverity.High => ConsoleColor.DarkYellow,
        AlertSeverity.Medium => ConsoleColor.Yellow,
        _ => ConsoleColor.Gray
    };

    Console.ForegroundColor = color;
    Console.WriteLine($"[{alert.Severity.ToString().ToUpper()}] {alert.RuleName}");
    Console.ResetColor();
    Console.WriteLine($"    Tecnica MITRE: {alert.MitreTechniqueId} - {alert.MitreTechniqueName}");
    Console.WriteLine($"    Detalle: {alert.Description}");
    Console.WriteLine($"    Eventos relacionados: {alert.RelatedEvents.Count}");
    Console.WriteLine(new string('-', 60));
}

if (alerts.Count == 0)
{
    Console.WriteLine("No se generaron alertas para el conjunto de eventos actual.");
}
