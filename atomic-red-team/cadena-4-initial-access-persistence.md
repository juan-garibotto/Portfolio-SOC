# Cadena 4 — Initial Access simulado → Persistence → Execution

**Fecha:** 27/10 · **Entorno:** Windows 10 Home (standalone, agente Wazuh instalado) · **Herramienta:** Atomic Red Team

## Resumen
Simulación de persistencia vía Run key del registro, precedida por un patrón recurrente de ruido propio del simulador (no del ataque), y acompañada de defense evasion mediante contenido con apariencia Base64 en el registro.

## Técnicas ejecutadas

| Hora | Técnica | Test | Rule ID | Detectado | Descripción de la regla |
|------|---------|------|---------|-----------|--------------------------|
| 17:52:32.623 | T1053.005 (Execution/Priv. Esc./Persistence) | — | 92154 | Sí | Process loaded taskschd.dll module |
| 17:52:36.828 | T1105 (Command and Control) | — | 92213 | Sí (Falso Positivo) | Executable file dropped in folder commonly used by malware |
| 17:56:42.576 | T1059.003 (Execution) | — | 92052 | Sí | Windows command prompt started by an abnormal process |
| 17:56:42.576 | T1027 + T1112 (Defense Evasion) | — | 92041 | Sí | Value added to registry key has Base64-like pattern |
| 17:56:42.591 | T1547.001 (Persistence / Priv. Esc.) | — | 92302 | Sí | Registry entry to be executed on next logon modified via reg.exe |

## Narrativa
El bloque inicial (T1053.005, rule 92154) muestra `taskschd.dll` cargado por `MoUsoCoreWorker.exe` — proceso legítimo de Windows Update. Inmediatamente después aparece un T1105 (rule 92213) marcando `DismHost.exe` dropeado en una carpeta temporal, con proceso padre `cleanmgr.exe` y usuario `vboxuser`. Este patrón —`cleanmgr.exe`/`MoUsoCoreWorker.exe` seguidos de drops en `%TEMP%`— se repite en varias de las cadenas de este lab y corresponde a **comportamiento normal de limpieza/actualización de Windows coincidiendo en el tiempo con la ejecución del atomic**, no a la técnica en sí.

La parte real de la cadena ocurre después: desde CMD se ejecuta `REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "ATOMIC RED TEAM" /t REG_SZ /F /D "C:\PATH\ATOMICREDTEAM.EXE"`, lo cual dispara dos detecciones en el mismo milisegundo: la regla 92041 (patrón Base64 en valor de registro, defense evasion) y la 92302 (persistencia vía Run key, detectada específicamente por el uso de `reg.exe` desde línea de comandos para modificar la clave).

## Falsos positivos identificados
- **T1105 / rule 92213 (`DismHost.exe` vía `cleanmgr.exe`):** falso positivo. Es actividad legítima de limpieza de Windows que coincidió temporalmente con la ejecución del atomic, no parte de la cadena de ataque simulada. Se documenta explícitamente para no inflar artificialmente el conteo de detecciones reales.

## Conclusión
El par de reglas 92041 + 92302 disparando juntas en el mismo instante es un buen ejemplo de **detección por redundancia**: dos reglas independientes (una mirando el contenido del valor, otra mirando el proceso que lo modificó) confirmando la misma técnica desde ángulos distintos — reduce sustancialmente la probabilidad de que sea casualidad, y es el tipo de correlación que le da más confianza a un analista para escalar una alerta.

## Referencias
- https://attack.mitre.org/techniques/T1053/005/
- https://attack.mitre.org/techniques/T1105/
- https://attack.mitre.org/techniques/T1027/
- https://attack.mitre.org/techniques/T1112/
- https://attack.mitre.org/techniques/T1547/001/
