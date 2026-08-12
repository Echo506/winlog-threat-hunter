using WinlogThreatHunter.EventCollector;

namespace WinlogThreatHunter.AttackSimulator;

/// <summary>
/// Genera eventos sinteticos que emulan comportamiento de ataque real,
/// utiles para validar el motor de correlacion sin depender de un
/// entorno comprometido. Cada metodo representa un escenario de MITRE ATT&CK.
/// </summary>
public sealed class ScenarioGenerator
{
    private readonly Random _random = new();

    /// <summary>
    /// Escenario 1: Fuerza bruta (T1110). Genera N eventos 4625 (fallo de logon)
    /// contra el mismo usuario en una ventana corta de tiempo.
    /// </summary>
    public List<SecurityEvent> GenerateBruteForce(string targetUser = "admin", int attempts = 8, string ip = "203.0.113.45")
    {
        var events = new List<SecurityEvent>();
        var start = DateTime.UtcNow.AddMinutes(-5);

        for (int i = 0; i < attempts; i++)
        {
            events.Add(new SecurityEvent
            {
                EventId = 4625,
                Channel = "Security",
                Provider = "Microsoft-Windows-Security-Auditing",
                TimeCreated = start.AddSeconds(i * 10),
                Computer = "WORKSTATION01",
                TargetUserName = targetUser,
                IpAddress = ip,
                RawMessage = $"Fallo de inicio de sesion para la cuenta {targetUser} desde {ip}"
            });
        }

        return events;
    }

    /// <summary>
    /// Escenario 2: Escalamiento de privilegios (T1098). Crea una cuenta (4720)
    /// y la agrega inmediatamente a un grupo administrativo (4732).
    /// </summary>
    public List<SecurityEvent> GeneratePrivilegeEscalation(string newUser = "svc_temp")
    {
        var created = DateTime.UtcNow.AddMinutes(-3);

        return new List<SecurityEvent>
        {
            new SecurityEvent
            {
                EventId = 4720,
                Channel = "Security",
                Provider = "Microsoft-Windows-Security-Auditing",
                TimeCreated = created,
                Computer = "DC01",
                TargetUserName = newUser,
                RawMessage = $"Se creo la cuenta de usuario {newUser}"
            },
            new SecurityEvent
            {
                EventId = 4732,
                Channel = "Security",
                Provider = "Microsoft-Windows-Security-Auditing",
                TimeCreated = created.AddMinutes(1),
                Computer = "DC01",
                TargetUserName = newUser,
                RawMessage = $"Se agrego {newUser} al grupo Administrators"
            }
        };
    }

    /// <summary>
    /// Escenario 3: Limpieza de logs (T1070). Simula el evento 1102
    /// (log de seguridad borrado), tipico de un atacante cubriendo sus huellas.
    /// </summary>
    public List<SecurityEvent> GenerateLogClearing(string actor = "admin")
    {
        return new List<SecurityEvent>
        {
            new SecurityEvent
            {
                EventId = 1102,
                Channel = "Security",
                Provider = "Microsoft-Windows-Eventlog",
                TimeCreated = DateTime.UtcNow,
                Computer = "DC01",
                SubjectUserName = actor,
                RawMessage = "El registro de auditoria de seguridad se borro"
            }
        };
    }

    /// <summary>
    /// Genera un conjunto combinado de eventos benignos y maliciosos,
    /// util para probar que las reglas no generan falsos positivos
    /// sobre trafico normal.
    /// </summary>
    public List<SecurityEvent> GenerateMixedTraffic(int benignCount = 20)
    {
        var events = new List<SecurityEvent>();
        var start = DateTime.UtcNow.AddHours(-1);

        for (int i = 0; i < benignCount; i++)
        {
            events.Add(new SecurityEvent
            {
                EventId = 4624, // logon exitoso
                Channel = "Security",
                Provider = "Microsoft-Windows-Security-Auditing",
                TimeCreated = start.AddMinutes(_random.Next(0, 60)),
                Computer = "WORKSTATION02",
                TargetUserName = $"user{_random.Next(1, 10)}",
                RawMessage = "Inicio de sesion exitoso"
            });
        }

        events.AddRange(GenerateBruteForce());
        events.AddRange(GeneratePrivilegeEscalation());
        events.AddRange(GenerateLogClearing());

        return events.OrderBy(e => e.TimeCreated).ToList();
    }
}
