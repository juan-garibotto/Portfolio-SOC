# Cadena N — Execution + Persistence

**Fecha:** 24/11 · **Entorno:** Windows 10 Home (standalone, agente Wazuh instalado) · **Herramienta:** Atomic Red Team

## Resumen
Ejecución inicial vía PowerShell ofuscado y cmd, seguida de dos mecanismos de persistencia distintos montados casi en el mismo segundo: una Run key en HKCU y una scheduled task. El objetivo de la cadena es dejar el pie dentro y asegurar la vuelta.

## Técnicas ejecutadas

| Hora | Técnica | Test | Rule ID | Detectado | Descripción de la regla |
|------|---------|------|---------|-----------|--------------------------|
| 17:16:08 | T1059.001 (Execution) | T1059.001-17 | 92032 | Sí | Suspicious Windows cmd shell execution |
| 17:16:34 | T1059.003 (Execution) | T1059.003-1 | 92052 | Sí | Windows command prompt started by an abnormal process |
| 17:17:05 | T1547.001 (Persistence) | T1547.001-1 | 92041 | Sí | Value added to registry key has Base64-like pattern |
| 17:17:05.985 | T1053.005 (Persistence) | T1053.005-1 | 92052 | Sí | Suspicious Windows cmd shell execution |

## Narrativa — la cadena causal
Arranco con un `powershell.exe -e` cargado de base64. La regla 92032 lo levanta, pero cuando miro el campo me doy cuenta de que la detección pega sobre el blob codificado, no sobre lo que el comando hacía realmente por dentro. Fui a buscar el evento 4104 para ver el scriptblock decodificado y no estaba: el canal `PowerShell/Operational` no está siendo ingerido por el agente. Contra este test da igual porque la línea de comando alcanzó, pero es algo que tengo que corregir, porque frente a un encoded command con algo real adentro me quedaría sin la única fuente que ve a través del encoding.

Después, la ejecución salta a cmd (92052) y de ahí a las dos persistencias. La Run key la escribe un `REG ADD` apuntando a `HKCU\...\CurrentVersion\Run`, y la 92041 la caza — aunque el nombre de la regla habla de un patrón tipo base64 y el dato era una ruta común, así que el match es medio flojo; el ancla real de esta técnica es el `TargetObject` terminando en `\Run`, no el contenido del valor. Casi en el mismo segundo entra la scheduled task: `SCHTASKS /Create /SC ONCE /TN spawn /TR cmd.exe /ST 20:10`, lanzada desde un cmd. Dos caminos de vuelta montados en paralelo.

## Falsos positivos identificados
Ninguno real, pero dejo anotada la 92041: disparó por un patrón "tipo base64" sobre una ruta que no lo era. Es una regla que puede ensuciar si uno la mira sola; lo que la hace confiable acá es el `TargetObject` sobre la Run key, no la descripción.

## Conclusión
La cadena se detectó entera a nivel de ejecución, pero el agujero no estuvo en ninguna regla sino en la fuente: sin el 4104, toda la visibilidad de PowerShell depende de la línea de comando. Es lo primero que voy a cerrar antes de seguir sumando técnicas de esta máquina.

## Referencias
- https://attack.mitre.org/techniques/T1059/001/
- https://attack.mitre.org/techniques/T1059/003/
- https://attack.mitre.org/techniques/T1547/001/
- https://attack.mitre.org/techniques/T1053/005/
