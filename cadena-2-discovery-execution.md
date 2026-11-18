# Cadena 2 — Discovery / Execution

**Fecha:** 26/10 · **Entorno:** Windows 10 Home (standalone, agente Wazuh instalado) · **Herramienta:** Atomic Red Team

## Resumen
Cadena de ejecución desde un shell CMD lanzado de forma anómala, seguida de comandos de descubrimiento de sistema y de cuentas, todo detectado por el ruleset default de Wazuh.

## Técnicas ejecutadas

| Hora | Técnica | Test | Rule ID | Detectado | Descripción de la regla |
|------|---------|------|---------|-----------|--------------------------|
| 18:16:59 | T1059.003 (Execution) | — | 92052 | Sí | Windows command prompt started by an abnormal process |
| 18:17:01 | T1087 + T1059.003 (Discovery + Execution) | — | 92032 | Sí | Suspicious Windows CMD shell execution |
| 18:18:24 | T1087 + T1059.003 (Discovery) | — | 92032 | Sí | Discovery activity (findstr "Active Disc/") |

## Narrativa
El CMD se inicia desde `C:\Users\vboxuser\AppData\Local\Temp\` (directorio típico de ejecución de atomics), y desde ahí se corre una secuencia de reconocimiento del sistema: se confirma IP, información de sistema, hora y modelo del equipo en consola. Inmediatamente después se ejecutan comandos de enumeración de cuentas (`whoami`, `useraccount get /ALL`), con la salida derivada a un archivo `usernames.txt` — un patrón típico de lo que un atacante real haría tras obtener ejecución de código, para mapear a quién tiene comprometido antes de decidir el siguiente paso.

Más tarde, en la misma sesión, se detecta un segundo patrón de discovery (`server: localhost | findstr "Active Disc/"`), también correctamente clasificado bajo T1087/T1059.003.

## Falsos positivos identificados
Ninguno en esta cadena — las tres detecciones corresponden directamente a la actividad simulada, sin ruido adicional del framework de testing.

## Conclusión
Esta cadena confirma que Wazuh, con el ruleset default, distingue correctamente entre un CMD iniciado de forma normal y uno "abnormal" (lanzado por un proceso padre inusual), y que el encadenamiento Discovery → Execution queda bien representado temporalmente en el dashboard, permitiendo reconstruir la secuencia completa del atacante sin ambigüedad.

## Referencias
- https://attack.mitre.org/techniques/T1059/003/
- https://attack.mitre.org/techniques/T1087/
