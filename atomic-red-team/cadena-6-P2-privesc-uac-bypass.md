# Cadena N — Privilege Escalation vía UAC bypass

**Fecha:** 24/11 · **Entorno:** Windows 10 Home (standalone, agente Wazuh instalado) · **Herramienta:** Atomic Red Team

## Resumen
Dos variantes del mismo bypass de UAC —fodhelper y computerdefaults— que llegan a integridad alta sin generar el prompt de consentimiento. Lo interesante no es que las dos funcionen, sino que una sola regla las detecta a las dos, y por el motivo correcto.

## Técnicas ejecutadas

| Hora | Técnica | Test | Rule ID | Detectado | Descripción de la regla |
|------|---------|------|---------|-----------|--------------------------|
| 17:21:10 | T1548.002 (Priv. Esc.) | T1548.002-4 / -5 | 92306 | Sí | PowerShell added a subkey associated with UAC bypass by auto-elevated processes |
| 17:21:10 | T1548.002 (Priv. Esc.) | T1548.002-4 | 92046 | Sí | fodhelper.exe execution |
| 17:21:10 | T1548.002 (Priv. Esc.) | T1548.002-5 | 92052 | Sí | abnormal process (ComputerDefaults.exe) |

## Narrativa — la cadena causal
Las dos técnicas abusan del mismo mecanismo. Primero escribo en `HKCU\Software\Classes\ms-settings\shell\open\command`, con el truco del `DelegateExecute` vacío. Después lanzo `fodhelper.exe` (y más tarde `computerdefaults.exe`): son binarios firmados de Windows marcados como auto-elevados, así que suben a integridad alta sin pedir UAC, y al arrancar leen esa clave de HKCU y ejecutan lo que dejé ahí. Elevación sin consentimiento.

Lo que me importa es cómo lo detectó Wazuh. La 92306 pegó sobre el `TargetObject` de la clave de registro —`...\ms-settings\shell\open\command\DelegateExecute`— y no sobre el nombre del binario. Por eso la misma regla levantó las dos variantes: fodhelper y computerdefaults cambian el ejecutable, pero los dos pasan por la misma clave. Esa es la forma correcta de escribir la detección de esta familia: anclar en el comportamiento de registro, no en el proceso, porque hay una docena de binarios auto-elevados que hacen lo mismo y una regla por binario sería una pelea perdida.

## Falsos positivos identificados
Ninguno. Una escritura sobre `ms-settings\shell\open\command` en HKCU no tiene uso legítimo normal; cuando aparece esa clave, es bypass casi siempre.

## Conclusión
Es el contraejemplo de las reglas que dependen de la línea de comando: acá la detección mira la causa (la clave que habilita la auto-elevación) y no el síntoma (el binario que corre). Una sola lógica cubre toda la familia de bypasses que pasan por ese path.

## Referencias
- https://attack.mitre.org/techniques/T1548/002/
