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

### 2. [`atomic-red-team/`](atomic-red-team/) — Validación de cobertura
Cadenas de técnicas ejecutadas con Atomic Red Team sobre la máquina Windows 10 Home, usadas para confirmar qué detecta el ruleset **default** de Wazuh y para practicar la habilidad más cotidiana de un SOC analyst: triagear alertas, distinguir señal de ruido, y documentar falsos positivos con criterio. Incluye una cadena de kill chain completa (Execution → Impact) en endpoint, donde el default cubrió la mayoría pero aparecieron gaps de configuración —el canal `PowerShell/Operational` sin ingerir (sin Event 4104) y el `ProcessAccess` acotado que dejó el dump de LSASS detectado solo por línea de comando— que motivaron las primeras reglas custom de endpoint (rango 100500+).

## Notas de metodología

Cada writeup documenta no solo lo que funcionó, sino los errores de configuración cometidos en el camino (por ejemplo, confundir DACL con SACL al auditar DCSync) y los falsos positivos identificados — incluyendo un caso donde el mismo Rule ID (92154) significa cosas completamente distintas según el contexto (Cadena 1 vs Cadena 3 de Atomic Red Team), y un caso donde la ausencia de una alerta es en sí misma el hallazgo más importante (Cadena 5 — gap de visibilidad de red). 
