# Cadena 3 — Credential Access + Discovery + Ejecución con privilegios SYSTEM

**Fecha:** 27/10 · **Entorno:** Windows 10 Home (standalone, agente Wazuh instalado) · **Herramienta:** Atomic Red Team

## Resumen
Cadena completa de lateral movement simulado seguido de persistencia vía scheduled task, con escalación efectiva a privilegios SYSTEM confirmada en la telemetría — no un falso positivo, sino una cadena causal real entre dos técnicas.

## Técnicas ejecutadas

| Hora | Técnica | Test | Rule ID | Detectado | Descripción de la regla |
|------|---------|------|---------|-----------|--------------------------|
| 17:26:59 | T1570 (Lateral Movement) | — | 92217 | Sí | Executable dropped in Windows root folder |
| 17:26:59 (+) | T1053.005 (Execution/Persistence/Priv. Esc.) | — | 92154 | Sí | Process loaded taskschd.dll module |
| 17:29:26.745 | T1059.003 + T1574.001 | — | 92036 | Sí | net.exe binary started by a Windows Shell |
| 17:29:26.761 | T1087 (Discovery) | — | 92039 | Sí | net.exe account discovery (NET1 USER /DOMAIN) |
| 17:29:27.672 | T1087 (Discovery) | — | 92031 | Sí | Discovery activity (NET1 GROUP /DOMAIN) |

## Narrativa — la cadena causal
Esta es la cadena más relevante de las 5 para demostrar análisis, porque conecta dos eventos que podrían leerse como independientes pero no lo son:

1. **T1570** deja un binario en la raíz de `C:\Windows\` (rule 92217)
2. Inmediatamente después, **T1053.005** (rule 92154) muestra `taskschd.dll` cargado, pero esta vez con `eventdata.user = NT AUTHORITY\SYSTEM` y `eventdata.Image = C:\WINDOWS\SYSTEM32\TASKHOSTW.EXE`

La lectura correcta: el binario dropeado en el paso 1 fue persistido vía scheduled task, y esa tarea se ejecutó después bajo `taskhostw.exe` con privilegios SYSTEM. A diferencia de la Cadena 1 (donde el mismo rule.id 92154 bajo `NT AUTHORITY\Servicio de red` era ruido del scheduler de Windows), acá el contexto —el binario recién dropeado, el usuario SYSTEM, y la secuencia temporal inmediata— confirma que es una **escalación de privilegio real combinada con persistencia**, no actividad legítima del sistema.

Después de este primer bloque, una segunda sub-cadena de reconocimiento de dominio se ejecuta desde CMD: `net user /domain` y `net group /domain`, correctamente etiquetados como T1059.003 → T1574.001 (ejecución del binario `net.exe` desde un shell) y T1087 (discovery de cuentas y grupos de dominio) en dos eventos consecutivos.

## Falsos positivos identificados
Ninguno — esta cadena es la contraparte directa de la Cadena 1: mismo rule.id (92154) pero esta vez **no** es falso positivo, gracias al contexto (usuario SYSTEM + binario recién dropeado + secuencia temporal).

## Conclusión
Esta cadena es el mejor ejemplo del lab para explicar por qué el mismo Rule ID puede significar cosas completamente distintas según el contexto — y por qué un analista no puede triagear una alerta aislada sin mirar qué pasó inmediatamente antes y quién es el usuario/proceso padre involucrado.

## Referencias
- https://attack.mitre.org/techniques/T1570/
- https://attack.mitre.org/techniques/T1053/005/
- https://attack.mitre.org/techniques/T1059/003/
- https://attack.mitre.org/techniques/T1087/
