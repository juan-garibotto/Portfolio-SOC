# Cadena 1 — Execution / Persistence / Privilege Escalation

**Fecha:** 26/10 · **Entorno:** Windows 10 Home (standalone, agente Wazuh instalado) · **Herramienta:** Atomic Red Team

## Resumen
Validación de cobertura del ruleset **default** de Wazuh (no reglas custom) contra dos técnicas encadenadas de ejecución y persistencia vía scheduled tasks y PowerShell anidado.

## Técnicas ejecutadas

| Hora | Técnica | Test | Rule ID | Detectado | Descripción de la regla |
|------|---------|------|---------|-----------|--------------------------|
| 17:28:09.149 | T1053.005 (Execution / Persistence / Priv. Esc.) | Number 7 | 92154 | Sí | Process loaded taskschd.dll module |
| 17:42:51 | T1059.001 (Execution) — disparó también T1053.005-4 | — | 92027 | Sí | Powershell process spawned powershell instance |

## Narrativa
La primera prueba (T1053.005 #7) crea una scheduled task, y Wazuh la detecta correctamente vía carga del módulo `taskschd.dll` en el proceso. La segunda prueba (T1059.001) generó una cadena de PowerShell anidado (un proceso PowerShell lanzando otra instancia de PowerShell), detectado por la regla default 92027.

Durante esta segunda prueba aparecieron además dos eventos adicionales relevantes para el análisis de falsos positivos:
- Un **T1105** (rule.id 92213, "Executable file dropped in folder commonly used by malware") sobre el archivo `__PSScriptPolicyTest_*.ps1` en `%TEMP%`
- Un **T1053.005** (rule.id 92154) con usuario `NT AUTHORITY\Servicio de red` y el mismo patrón de `taskschd.dll`

## Falsos positivos identificados
Ambos eventos adicionales mencionados arriba son **falsos positivos conocidos del propio framework de Atomic Red Team**, no del ataque simulado:
- El archivo `__PSScriptPolicyTest_*.ps1` es generado automáticamente por PowerShell al verificar la política de ejecución de scripts antes de correr cada atomic test — no es parte de la técnica, es overhead del harness de testing
- La carga de `taskschd.dll` bajo el contexto `NT AUTHORITY\Servicio de red` corresponde a actividad legítima del scheduler de Windows, no a la scheduled task creada por el atomic

**Nota de proceso:** este mismo patrón de falso positivo (`__PSScriptPolicyTest_`) fue identificado y silenciado más adelante con una regla de supresión (rule ID 100100) en el `local_rules.xml` del lab de AD — es el mismo hallazgo reutilizado entre ambos entornos.

## Conclusión
El ruleset default de Wazuh detectó correctamente las dos técnicas sin necesidad de reglas custom. El valor de esta cadena está en identificar y documentar el ruido propio del framework de testing, para no confundirlo con hallazgos reales en una investigación futura.

## Referencias
- https://attack.mitre.org/techniques/T1053/005/
- https://attack.mitre.org/techniques/T1059/001/
- https://attack.mitre.org/techniques/T1105/
