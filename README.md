# Home Lab — Attack & Detection Portfolio

Portfolio de ejercicios de ataque y detección en un home lab propio, construido para practicar y documentar el ciclo completo de una investigación desde la perspectiva de blue team: ejecutar la técnica, generar la telemetría, y escribir (o validar) la detección.

## Entorno

El lab tiene dos componentes independientes, unidos por un mismo backend de telemetría:

| Componente | Rol | Detalle |
|---|---|---|
| pfSense | Segmentación de red | Separa la red interna del lab ("SOC NET") del resto |
| Windows Server 2022 (`DC01`) | Domain Controller (`lab.local`) | Usuarios, grupos y cuentas de servicio con configuraciones vulnerables intencionales (SPNs, cuentas sin preauth, Domain Admin) |
| Kali Linux | Atacante | Impacket, NetExec, Hashcat |
| Windows 10 Home (standalone) | Víctima para Atomic Red Team | No forma parte del dominio — usada para validar cobertura de detección técnica por técnica, sin necesidad de infraestructura AD |
| Wazuh (manager en `192.168.10.7`) | SIEM | Agentes en ambas máquinas Windows. Reglas custom en el rango 100000+ (`local_rules.xml`); el resto de las detecciones usa el ruleset default (rango 9xxxx) |

## Dos tipos de trabajo distintos, documentados por separado

Este portfolio muestra dos habilidades complementarias de un analista:

### 1. [`detecciones/`](detecciones/) — Detection Engineering
Una cadena de ataque encadenada y realista contra el Domain Controller (Discovery → Kerberoasting → AS-REP Roasting → DCSync). Acá el ruleset default de Wazuh **no cubría** las técnicas, así que cada writeup incluye la regla custom escrita desde cero (Wazuh + Sigma), verificada funcionando contra el ataque real.

| # | Fase | Técnica MITRE | Estado |
|---|------|---------------|--------|
| 1 | [Discovery](detecciones/discovery/writeup.md) | T1087.002, T1069.002, T1018 | Ejecutado (sin regla — ver writeup) |
| 2 | [Kerberoasting](detecciones/kerberoasting-rc4/writeup.md) | T1558.003 | Ejecutado + Detectado (regla custom) |
| 3 | [AS-REP Roasting](detecciones/as-rep-roasting/writeup.md) | T1558.004 | Ejecutado + Detectado (regla custom) |
| 4 | [DCSync](detecciones/dcsync/writeup.md) | T1003.006 | Ejecutado + Detectado (regla custom) |

### 2. [`atomic-red-team/`](atomic-red-team/) — Validación de cobertura
Cinco cadenas de técnicas ejecutadas con Atomic Red Team sobre la máquina Windows 10 Home, usadas para confirmar qué detecta el ruleset **default** de Wazuh sin tocar una sola regla, y para practicar la habilidad más cotidiana de un SOC analyst: triagear alertas, distinguir señal de ruido, y documentar falsos positivos con criterio.

| # | Cadena | Fecha | Técnicas principales | Falsos positivos documentados |
|---|--------|-------|----------------------|-------------------------------|
| 1 | [Execution / Persistence / Priv. Esc.](atomic-red-team/cadena-1-execution-persistence/writeup.md) | 26/10 | T1053.005, T1059.001 | 2 |
| 2 | [Discovery / Execution](atomic-red-team/cadena-2-discovery-execution/writeup.md) | 26/10 | T1059.003, T1087 | 0 |
| 3 | [Lateral Movement / Priv. Esc.](atomic-red-team/cadena-3-lateral-movement-privesc/writeup.md) | 27/10 | T1570, T1053.005, T1059.003, T1087 | 0 (cadena causal confirmada) |
| 4 | [Initial Access / Persistence](atomic-red-team/cadena-4-initial-access-persistence/writeup.md) | 27/10 | T1053.005, T1027, T1112, T1547.001 | 1 |
| 5 | [Collection / Exfiltration](atomic-red-team/cadena-5-collection-exfiltration/writeup.md) | 27/10 | T1005, T1041 | 1 (+ gap de visibilidad de red documentado) |


## Notas de metodología

Cada writeup documenta no solo lo que funcionó, sino los errores de configuración cometidos en el camino (por ejemplo, confundir DACL con SACL al auditar DCSync) y los falsos positivos identificados — incluyendo un caso donde el mismo Rule ID (92154) significa cosas completamente distintas según el contexto (Cadena 1 vs Cadena 3 de Atomic Red Team), y un caso donde la ausencia de una alerta es en sí misma el hallazgo más importante (Cadena 5 — gap de visibilidad de red). 
