# Fase 2 — Kerberoasting (RC4)

## Resumen
Extracción y crackeo offline del hash de una cuenta de servicio (`svc_sql`) con SPN configurado, abusando de que cualquier usuario autenticado del dominio puede solicitar un ticket de servicio (TGS) para una cuenta con SPN, y que dicho ticket puede venir cifrado con RC4 (derivado del NTLM hash de la cuenta de servicio), lo cual permite crackeo offline sin generar más tráfico contra el DC después de obtenido el ticket.

- **Táctica MITRE ATT&CK:** Credential Access
- **Técnica:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
- **Cuenta atacante:** `jperez` (usuario estándar)
- **Cuenta objetivo:** `svc_sql` (cuenta de servicio con SPN `MSSQLSvc/sql01.lab.local:1433`)

## Prerrequisitos
- Credenciales de cualquier usuario de dominio válido
- Conocimiento de al menos una cuenta con SPN configurado (obtenido en Fase 1 — Discovery)
- Impacket y Hashcat instalados en Kali

## Ataque

```bash
# Solicitar TGS para todas las cuentas con SPN y volcar los hashes crackeables
impacket-GetUserSPNs lab.local/jperez:'Verano2026!' -dc-ip 192.168.10.12 -request

# Guardar el hash obtenido en un archivo (formato $krb5tgs$23$...)
# Crackeo offline con Hashcat (modo 13100 = Kerberoasting TGS-REP RC4)
hashcat -m 13100 svc_sql.hash wordlist.txt
```

Resultado: password de `svc_sql` recuperada (`Summer2026!`), **sin haber generado ningún intento de autenticación fallida contra el DC** — todo el crackeo ocurrió offline, en la máquina atacante.

## Telemetría generada
- **Event ID 4769** (A Kerberos service ticket was requested) en el DC, con `TicketEncryptionType = 0x17` (RC4), para el SPN `MSSQLSvc/sql01.lab.local:1433`
- Ningún evento de fallo de autenticación — esta es la clave de por qué Kerberoasting es tan sigiloso: la solicitud de un TGS es una operación legítima y exitosa del protocolo Kerberos

## Detección

**Regla Wazuh (`local_rules.xml`):**

```xml
<group name="windows,kerberoasting,">
  <rule id="100200" level="5">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4769$</field>
    <description>Kerberos service ticket requested (TGS-REQ)</description>
    <group>kerberos_ticket,</group>
  </rule>
  <rule id="100201" level="12">
    <if_sid>100200</if_sid>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <description>Possible Kerberoasting: TGS requested with weak RC4 encryption for $(win.eventdata.serviceName)</description>
    <mitre><id>T1558.003</id></mitre>
    <group>kerberoasting,attack,</group>
  </rule>
</group>
```

**Regla Sigma equivalente:**

```yaml
title: Possible Kerberoasting - RC4 TGS Request
id: <generar-uuid>
status: experimental
description: Detects a Kerberos service ticket (TGS) requested with weak RC4 encryption, a common indicator of Kerberoasting attacks
references:
    - https://attack.mitre.org/techniques/T1558/003/
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
    condition: selection
falsepositives:
    - Legacy applications or systems that don't support AES encryption
level: high
tags:
    - attack.credential_access
    - attack.t1558.003
```

**Verificado:** alerta confirmada en el dashboard de Wazuh tras re-ejecutar `GetUserSPNs` con la regla activa.

## Falsos positivos
- Aplicaciones legacy o sistemas (algunos sistemas industriales, impresoras, dispositivos embebidos) que no soportan AES y negocian RC4 por compatibilidad
- Mitigación real: forzar AES en todas las cuentas de servicio (`msDS-SupportedEncryptionTypes`) elimina este vector por completo, no solo lo detecta

## Cómo lo investigaría en un SOC
1. Confirmar si la cuenta de servicio objetivo soporta/debería soportar AES — si sí, la solicitud en RC4 es altamente sospechosa por sí sola
2. Revisar el volumen: una sola solicitud RC4 puede ser ruido; múltiples SPNs distintos solicitados por la misma cuenta en poco tiempo es un patrón de herramienta automatizada (GetUserSPNs/Rubeus)
3. Pivotear sobre la cuenta origen (en este caso `jperez`) para ver si hubo actividad de enumeración previa (Fase 1) — confirma intencionalidad
4. Si la cuenta objetivo termina autenticándose poco después desde un origen distinto al habitual, correlacionar con el password cracking exitoso

## Evasión posible
- Solicitar SPNs de a uno, espaciados en el tiempo, para no generar volumen anómalo
- Usar Rubeus con la opción de forzar solamente el servicio específico que interesa, en lugar de un barrido completo (`/outfile` dirigido)
- Si el atacante ya tiene foothold interno, el tráfico se mezcla con el ruido normal de autenticación Kerberos del dominio

## Referencias
- https://attack.mitre.org/techniques/T1558/003/
