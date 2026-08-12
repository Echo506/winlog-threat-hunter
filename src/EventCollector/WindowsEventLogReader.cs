using System.Diagnostics.Eventing.Reader;

namespace WinlogThreatHunter.EventCollector;

/// <summary>
/// Lee eventos de los canales de Windows Event Log (Security, System)
/// y los normaliza al modelo <see cref="SecurityEvent"/>.
/// Requiere ejecutarse en Windows con permisos de lectura sobre el canal.
/// </summary>
public sealed class WindowsEventLogReader
{
    private readonly string _channel;

    public WindowsEventLogReader(string channel = "Security")
    {
        _channel = channel;
    }

    /// <summary>
    /// Devuelve los eventos más recientes del canal, opcionalmente filtrados por EventId.
    /// </summary>
    public IEnumerable<SecurityEvent> ReadRecent(int maxEvents = 100, IReadOnlySet<int>? eventIds = null)
    {
        var query = new EventLogQuery(_channel, PathType.LogName)
        {
            ReverseDirection = true
        };

        using var reader = new EventLogReader(query);
        int count = 0;

        for (EventRecord? record = reader.ReadEvent(); record != null; record = reader.ReadEvent())
        {
            using (record)
            {
                if (eventIds is not null && record.Id != 0 && !eventIds.Contains(record.Id))
                    continue;

                yield return Normalize(record);
                count++;

                if (count >= maxEvents)
                    yield break;
            }
        }
    }

    private static SecurityEvent Normalize(EventRecord record)
    {
        string? subjectUser = null;
        string? targetUser = null;
        string? ipAddress = null;

        try
        {
            var properties = record.Properties;
            // El orden de las propiedades varía según el EventId;
            // en una implementación completa se debería mapear por XPath/plantilla.
            if (properties.Count > 5)
            {
                subjectUser = properties[1]?.Value?.ToString();
                targetUser = properties[5]?.Value?.ToString();
            }

            if (properties.Count > 19)
                ipAddress = properties[19]?.Value?.ToString();
        }
        catch
        {
            // Defensivo: si el layout de propiedades no coincide, se ignora el detalle.
        }

        return new SecurityEvent
        {
            EventId = record.Id,
            Channel = record.LogName ?? "Security",
            Provider = record.ProviderName ?? string.Empty,
            TimeCreated = record.TimeCreated ?? DateTime.MinValue,
            Computer = record.MachineName,
            SubjectUserName = subjectUser,
            TargetUserName = targetUser,
            IpAddress = ipAddress,
            RawMessage = SafeFormatDescription(record)
        };
    }

    private static string SafeFormatDescription(EventRecord record)
    {
        try
        {
            return record.FormatDescription() ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }
}
