# Fase 1 — Discovery / Enumeración de Active Directory

## Resumen
Primera fase del attack chain ejecutado contra el dominio `lab.local` (lab personal, aislado, sin conexión a redes de producción). Con credenciales de un usuario estándar del dominio se realizó enumeración de usuarios, grupos, y relaciones de privilegio, orientada a identificar cuentas de servicio con SPN (candidatas a Kerberoasting) y cuentas vulnerables a AS-REP Roasting.

- **Entorno:** DC01 (Windows Server 2022, `lab.local`), Wazuh manager en `192.168.10.7`, atacante en Kali Linux
- **Cuenta utilizada:** `jperez` (usuario de dominio estándar, sin privilegios elevados)
- **Táctica MITRE ATT&CK:** Discovery
- **Técnicas:** T1087.002 (Account Discovery: Domain Account), T1069.002 (Permission Groups Discovery: Domain Groups), T1018 (Remote System Discovery)

## Prerrequisitos
- Credenciales válidas de un usuario de dominio (`jperez`), obtenidas asumiendo un escenario previo de phishing/OSINT (fuera de alcance de este lab)
- Conectividad de red hacia el DC (`192.168.10.12`)
- NetExec instalado en Kali

## Ataque

```bash
# Validar credenciales y enumerar SMB
netexec smb 192.168.10.12 -u jperez -p 'Verano2026!'

# Enumerar usuarios del dominio
netexec smb 192.168.10.12 -u jperez -p 'Verano2026!' --users

# Enumerar grupos del dominio (identificar Domain Admins, grupos privilegiados)
netexec smb 192.168.10.12 -u jperez -p 'Verano2026!' --groups

# Enumerar vía LDAP para más detalle de atributos
netexec ldap 192.168.10.12 -u jperez -p 'Verano2026!' --users
```

**Hallazgos relevantes de esta fase:**
- Identificación de la OU de usuarios (`Lab Users`), grupos custom (`SOC-Analysts`, `IT-Helpdesk`, `Finance`) y OU de cuentas de servicio (`Service Accounts`)
- Identificación de `adm_ana` como miembro del grupo Domain Admins (confirmado vía SID: `$DomainSid-512`, no por el nombre del grupo ya que el sistema está en español y los nombres en inglés no resuelven directamente)
- Identificación de `svc_sql` con SPN configurado (`MSSQLSvc/sql01.lab.local:1433`) → candidato a Kerberoasting
- Identificación de `svc_backup` con el flag `DoesNotRequirePreAuth` activo → candidato a AS-REP Roasting

## Telemetría generada
- Eventos de logon SMB (4624, tipo de logon 3) desde la IP de Kali hacia el DC
- Múltiples consultas LDAP del mismo origen en una ventana corta de tiempo

## Detección
No se implementó una regla custom de Wazuh para esta fase. La enumeración LDAP/SMB con credenciales válidas es, en el día a día, prácticamente indistinguible de actividad legítima de administración o de herramientas de inventario — bloquear o alertar sobre esto sin una línea base de comportamiento normal por cuenta generaría un volumen inmanejable de falsos positivos.

**Enfoque recomendado para producción (no implementado en este lab):** UEBA / detección por volumen anómalo de consultas LDAP por cuenta en una ventana de tiempo corta, comparado contra el baseline histórico de esa cuenta — no una regla estática de firma.

## Falsos positivos
- Administradores de AD realizando inventario o troubleshooting
- Herramientas de gestión de activos (SCCM, asset management) que enumeran el dominio regularmente
- Cualquier herramienta de BloodHound/sharphound usada legítimamente por el propio equipo de seguridad (purple team)

## Cómo lo investigaría en un SOC
Esta fase por sí sola no dispara ninguna alerta. El valor real de documentarla es como **contexto retroactivo**: si más adelante aparece una alerta de Kerberoasting o AS-REP Roasting sobre `svc_sql`/`svc_backup`, un analista debería poder pivotear hacia atrás en el tiempo sobre la misma cuenta/IP origen y encontrar esta actividad de enumeración previa, confirmando la cadena completa del ataque en lugar de tratar cada alerta como un evento aislado.

## Evasión posible
- Throttling de consultas (espaciar las queries en el tiempo para no generar picos de volumen)
- Usar herramientas nativas de Windows (`net user`, `net group`, PowerShell AD module) en lugar de herramientas ofensivas conocidas, para mezclarse con tráfico de administración legítimo
- Enumerar desde una cuenta y equipo ya comprometidos dentro de la red, evitando tráfico desde un host "externo" reconocible

## Referencias
- https://attack.mitre.org/techniques/T1087/002/
- https://attack.mitre.org/techniques/T1069/002/
- https://attack.mitre.org/techniques/T1018/
