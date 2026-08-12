# WinLog Threat Hunter

Plataforma SOC en C# que simula las capacidades básicas de un SIEM: recolección de eventos de Windows, correlación de reglas mapeadas a MITRE ATT&CK, dashboard de alertas y un simulador de ataques para generar telemetría de prueba.

Proyecto orientado a demostrar habilidades prácticas para roles de **SOC Analyst / Blue Team**: detección de amenazas, análisis de logs, triage de alertas y comprensión de tácticas y técnicas de adversarios.

## Objetivo

Demostrar de forma práctica el ciclo completo de detección en un SOC:

1. Generar o recolectar eventos (Windows Event Log).
2. Correlacionarlos contra reglas de detección basadas en TTPs de MITRE ATT&CK.
3. Elevar alertas con severidad y contexto.
4. Visualizarlas en un dashboard para triage.

## Arquitectura

```
winlog-threat-hunter/
├── src/
│   ├── EventCollector/       # Lectura de Windows Event Logs (Security, System)
│   ├── CorrelationEngine/    # Motor de reglas + mapeo a MITRE ATT&CK
│   ├── AttackSimulator/      # Generador de eventos sintéticos (fuerza bruta, persistencia, etc.)
│   └── Dashboard/            # UI de alertas en tiempo real
├── rules/                    # Definiciones de reglas de correlación (JSON/YAML)
├── tests/                    # Pruebas unitarias
└── README.md
```

### Módulos

**EventCollector**
Lee eventos del Visor de Eventos de Windows (`System.Diagnostics.Eventing.Reader`) desde los canales Security y System, normalizándolos a un modelo común (`SecurityEvent`).

**CorrelationEngine**
Aplica reglas de detección sobre el stream de eventos normalizados. Ejemplos de reglas iniciales:

| Regla | Técnica MITRE ATT&CK | Descripción |
|---|---|---|
| Múltiples fallos de autenticación | T1110 (Brute Force) | 5+ eventos 4625 desde el mismo origen en menos de 2 minutos |
| Creación de cuenta + asignación a grupo privilegiado | T1078 / T1098 | Evento 4720 seguido de 4732 sobre grupo Administrators |
| Ejecución de proceso inusual desde ubicación temporal | T1059 | Proceso lanzado desde `%TEMP%` o `%APPDATA%` |
| Limpieza de logs de seguridad | T1070 (Indicator Removal) | Evento 1102 (log cleared) |

**AttackSimulator**
Genera eventos sintéticos que disparan las reglas anteriores, permitiendo validar el motor de correlación sin necesidad de un entorno comprometido real. Útil para demos y pruebas automatizadas.

**Dashboard**
Interfaz (consola enriquecida o Blazor, según iteración) que muestra alertas activas, severidad, técnica ATT&CK asociada y línea de tiempo de eventos correlacionados.

## Stack técnico

- C# / .NET 8
- System.Diagnostics.Eventing.Reader (Windows Event Log API)
- MITRE ATT&CK framework (mapeo de reglas)
- xUnit (pruebas)

## Roadmap

- [ ] Modelo de datos común para eventos normalizados
- [ ] Motor de reglas basado en JSON configurables
- [ ] Simulador con al menos 5 escenarios de ataque
- [ ] Dashboard con severidad y filtros
- [ ] Exportación de alertas a CSV/JSON (formato tipo SIEM)
- [ ] Documentación de cada regla con referencia a MITRE ATT&CK

## Motivación

Este proyecto nace como parte de mi preparación para roles de **SOC Analyst**, aplicando conocimientos de ciberseguridad, análisis de logs y detección de amenazas en un caso de uso realista y verificable.

## Autor

Wilfrido Pérez Romero — [LinkedIn](https://linkedin.com/in/wilfridocostarica)
