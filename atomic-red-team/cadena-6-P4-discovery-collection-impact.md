# Cadena N — Discovery + Collection + Impact

**Fecha:** 24/11 · **Entorno:** Windows 10 Home (standalone, agente Wazuh instalado) · **Herramienta:** Atomic Red Team

## Resumen
El tramo final de la intrusión: reconocimiento del equipo y del dominio, recolección de archivos en un comprimido con contraseña, y destrucción de los puntos de recuperación como preámbulo típico de un ransomware. Casi todo se detectó por la línea de comando desde cmd.

## Técnicas ejecutadas

| Hora | Técnica | Test | Rule ID | Detectado | Descripción de la regla |
|------|---------|------|---------|-----------|--------------------------|
| 17:25:15 | T1033 (Discovery) | T1033-1 | 92052 | Sí | Suspicious Windows cmd shell execution |
| 17:25:16 | T1057 (Discovery) | T1057-1 | 92032 | Sí | Suspicious Windows cmd shell execution |
| 17:26:01 | T1087 / T1018 (Discovery) | T1087.002 | 92031/92034/92035/92036 | Sí | net.exe account/group discovery |
| 17:26:12 | T1560.001 (Collection) | T1560.001-1 | 92052 | Sí | Suspicious Windows cmd shell execution |
| 17:26:23 | T1490 (Impact) | T1490-1 | 92052/92032/92027 | Sí | Suspicious Windows cmd shell execution |

## Narrativa — la cadena causal
El reconocimiento arranca con un `whoami` y una tira de `quser` / `qwinsta` encadenados (T1033) para ver quién está en la máquina, sigue con `tasklist` (T1057) para los procesos, y después salta al dominio: `net view`, `net group "Domain Computers" /domain`. Acá hay un detalle que me gusta mostrar — la alerta final (92031) no la dispara `net.exe` sino `net1.exe`, que es el binario al que `net` delega el trabajo real. Si uno busca solo `net.exe` se pierde la mitad. Como la máquina es standalone, los comandos de dominio devuelven error, pero eso no importa para la detección: el comando se ejecuta y se loguea igual. La regla pega sobre la intención, no sobre el éxito.

De ahí paso a la recolección. `7z u archive.7z -pblue` arma un comprimido con contraseña — el `-p` es la parte que importa, porque un archivo cifrado con password es la forma clásica de preparar la exfiltración y de esquivar la inspección de contenido.

El cierre es el tramo de impacto, y es el más rico en comandos: `vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, `wbadmin delete catalog -quiet`, `bcdedit /set {default} recoveryenabled no`, y el `Get-WmiObject Win32_Shadowcopy | Delete` desde PowerShell. Es el playbook entero de pre-cifrado de un ransomware: borrar las shadow copies, el catálogo de backups y deshabilitar la recuperación de arranque, todo junto, para que la víctima no pueda volver atrás. Cada uno de esos comandos es alta fidelidad por sí solo.

## Falsos positivos identificados
Ninguno. El único punto a aclarar es el `net1.exe` como worker de `net.exe`: no es un falso positivo, pero sí algo a tener en cuenta al escribir reglas, porque la actividad real queda bajo el proceso delegado.

## Conclusión
Todo el tramo se apoyó en cmd y en la línea de comando, que es su fortaleza y su límite a la vez: un atacante que haga el mismo recon y el mismo borrado por API o WMI directo, sin tirar de cmd, apagaría buena parte de estas alertas. El bloque de impacto, en cambio, es difícil de evadir — los nombres de esos comandos son tan específicos que detectarlos es casi gratis. (Nota: el borrado de logs de esta misma corrida, T1070.001, me dio error de ejecución y quedó pendiente de validar.)

## Referencias
- https://attack.mitre.org/techniques/T1033/
- https://attack.mitre.org/techniques/T1057/
- https://attack.mitre.org/techniques/T1087/
- https://attack.mitre.org/techniques/T1018/
- https://attack.mitre.org/techniques/T1560/001/
- https://attack.mitre.org/techniques/T1490/
