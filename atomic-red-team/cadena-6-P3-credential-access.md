# Cadena N — Credential Access

**Fecha:** 24/11 · **Entorno:** Windows 10 Home (standalone, agente Wazuh instalado) · **Herramienta:** Atomic Red Team

## Resumen
Tres métodos distintos de volcado de LSASS más un barrido de credenciales en archivos. Los cuatro se detectaron, pero no con la misma calidad: solo uno disparó la regla de acceso real a la memoria; los demás se salvaron por la línea de comando. La cadena me sirvió para ver la diferencia entre estar cubierto y estar bien cubierto.

## Técnicas ejecutadas

| Hora | Técnica | Test | Rule ID | Detectado | Descripción de la regla |
|------|---------|------|---------|-----------|--------------------------|
| 17:21:49 | T1003.001 (Cred. Access) | procdump | 92052 | Sí | Suspicious Windows cmd shell execution |
| 17:21:49 | T1003.001 (Cred. Access) | comsvcs | 92027 | Sí | PowerShell execution |
| 17:22:27 | T1003.001 (Cred. Access) | rdrleakdiag | 92403 | Sí | LSASS accessed, possible credential dumping |
| 17:23:27 | T1552.001 (Cred. Access) | findstr | 92027 | Sí | PowerShell execution |

## Narrativa — la cadena causal
Los cuatro pasos buscan lo mismo —credenciales— pero cada uno se detectó por un motivo distinto, y ahí está lo que me quedé mirando.

`procdump -ma lsass.exe` volcó la memoria y lo levantó la 92052, que es una regla de shell anómala: me detectó por la línea de comando, no porque haya visto el acceso a LSASS. `comsvcs MiniDump` vía rundll32 hizo lo mismo por otra vía y lo cazó la 92027, otra vez por la línea de comando, porque corrió dentro de PowerShell. El único que disparó la 92403 fue `rdrleakdiag`, y esa sí está basada en Sysmon Event 10 (ProcessAccess): Wazuh vio el acceso real a la memoria de `lsass.exe`. De tres formas de robar de LSASS, una sola tocó la detección que mira la acción; las otras dos habrían pasado en silencio si el binario se llamara distinto o no dijera "lsass" en su comando.

El findstr (T1552.001) cerró la idea. Barrió archivos buscando `password` y lo detectó... la 92027. La misma regla que había levantado el dump de comsvcs. O sea, una regla genérica que dice "se ejecutó PowerShell" y nada más: dispara bien, pero no distingue si estoy volcando LSASS o leyendo un txt. Cobertura hay; atribución a la técnica, no.

La causa de fondo del hueco en LSASS no es la regla sino la telemetría: la config de Sysmon (SwiftOnSecurity) tiene el `ProcessAccess` acotado y por eso solo entró el acceso de rdrleakdiag. Para cerrarlo tengo que ampliar ese bloque para registrar los accesos a `lsass.exe` con máscaras de lectura de memoria sin importar qué proceso los haga, y después re-correr los tres métodos para confirmar que los tres generen Event 10.

## Falsos positivos identificados
Ninguno, pero con un matiz que me importa: la 92027 no es un falso positivo, es un verdadero positivo de baja especificidad. No se triagea igual el ruido que hay que filtrar que la señal correcta sin contexto suficiente. Acá el problema es lo segundo.

## Conclusión
Frente a una 92027 sola no puedo saber si estoy mirando un dump de LSASS o un findstr inofensivo. La especificidad de la regla define la calidad del triage, y la telemetría de la fuente —el Event 10— define el techo de lo que cualquier regla puede llegar a ver. Los dos son trabajo pendiente en esta máquina.

## Referencias
- https://attack.mitre.org/techniques/T1003/001/
- https://attack.mitre.org/techniques/T1552/001/
