# Reflexión — Threat Hunt Simulator (nivel Hard)

## Contexto
Resolví un ejercicio de threat hunting nivel Hard sobre un entorno simulado multi-host, con telemetría estilo SIEM (logs de PowerShell Script Block Logging, Sysmon/process creation, y eventos de red). El punto de partida fue un informe de inteligencia de amenazas con una hipótesis de trabajo y un puñado de indicadores iniciales — nada más. El resto había que reconstruirlo desde cero: el vector de entrada, el alcance real dentro del entorno, y si hubo exfiltración de datos.

No comparto acá los detalles específicos del caso (nombres, indicadores, rutas exactas) porque es contenido de una plataforma de pago y la idea de este post no es dar la solución, sino mostrar el proceso de pensamiento.

## Metodología que seguí

**1. Anclar en los indicadores más duros primero.** Con una IP de C2 y dos nombres de archivo como punto de partida, arranqué buscando coincidencias exactas de esos tres elementos en la telemetría, en vez de salir a explorar en general. Un indicador confirmado te da una marca de tiempo real desde la cual pivotear, y evita perder tiempo revisando actividad irrelevante.

**2. Una vez confirmado el ancla, pivotear en ambas direcciones en el tiempo.** Hacia adelante para ver qué hizo el atacante después de establecer el indicador confirmado (en mi caso, terminó en una exfiltración); hacia atrás para reconstruir cómo llegó hasta ahí (terminó siendo un script ejecutado manualmente por un usuario, no un exploit).

**3. Tratar cada hallazgo como una pregunta nueva, no como el final de la búsqueda.** Encontrar la exfiltración no cerró el caso — abrió la pregunta de qué datos específicos se llevaron, lo cual llevó a encontrar una fase de staging anterior, que a su vez reveló un movimiento lateral con una credencial robada, que a su vez llevó a encontrar de dónde salió esa credencial. Cada respuesta generó la siguiente pregunta — así se arma una cadena de ataque completa en vez de un conjunto de hallazgos sueltos.

**4. Verificar el alcance activamente, no asumirlo.** El entorno tenía varias cuentas de usuario con actividad registrada. En vez de asumir que todas estaban comprometidas (o que ninguna más lo estaba), investigué cada una contra la evidencia ya confirmada — buscando superposición real con los indicadores conocidos, no solo presencia en los logs.

## El error que cometí (y cómo lo corregí)

Durante la fase de verificación de alcance, encontré actividad de PowerShell de una cuenta distinta a la comprometida, en el mismo host que había sido blanco del movimiento lateral. Mi primera lectura fue que podía tratarse del atacante probando el acceso con la credencial robada antes de usarla para robar datos — una hipótesis razonable dado el timing.

Pero antes de darla por buena, revisé un campo específico del log que indica **desde dónde se originó esa sesión de PowerShell** (si fue una consola local interactiva, o una conexión remota entrante). Ese campo mostraba claramente que era una sesión **local**, no remota — lo cual descartaba por completo mi hipótesis inicial. Mirando el resto del contenido de esa sesión, resultó ser una tarea rutinaria y completamente legítima de la cuenta dueña de ese host, sin ninguna relación con el incidente.

La lección: **un mismo patrón superficial (misma cuenta, mismo host, timing cercano al incidente) puede tener explicaciones completamente opuestas**, y la diferencia entre "esto es el atacante" y "esto es ruido" a veces está en un solo campo del log que hay que saber buscar y saber interpretar correctamente — no alcanza con el patrón visual.

## El feedback que recibí

El ejercicio fue evaluado y aprobado, pero con una devolución que prefiero compartir en vez de esconder, porque fue más útil que la nota en sí. En resumen, señaló tres cosas:

1. **Falta de especificidad técnica en la documentación.** Tenía toda la evidencia necesaria (rutas completas, comandos exactos, nombres de claves de registro), pero al resumir para el reporte final simplifiqué de más — algo como "se ejecutó un script malicioso" en vez del comando completo con su ruta. Un reporte de threat hunting tiene que poder usarse como evidencia accionable para otro analista, no como un resumen narrativo.

2. **Alineación incorrecta de host/cuenta en algún punto de la cadena.** Cuando hay movimiento lateral de por medio, "¿dónde ocurrió esto realmente?" no siempre es obvio — un comando ejecutado desde un host pero que corre en otro puede quedar mal etiquetado si no se presta atención al detalle.

3. **Falta de completitud dentro de cada etapa documentada.** Al tratar de condensar la cadena en una cantidad limitada de pasos, terminé comprimiendo de más algunas fases, dejando afuera detalles (como el establecimiento del canal de control remoto, o el mecanismo específico de persistencia) que técnicamente merecían su propio espacio en el reporte, aunque cronológicamente estuvieran cerca de otro paso.

## Qué me llevo

El error de interpretación y el feedback apuntan en la misma dirección: **tengo el instinto para razonar la cadena de ataque, pero me falta disciplina en la documentación forense**. Son cosas distintas — una es analizar correctamente, la otra es registrar ese análisis de forma que sea útil y verificable para otra persona (o para mí mismo, revisándolo en seis meses). La segunda se entrena con repetición consciente: tratar cada reporte, desde ahora, como si alguien más fuera a actuar directamente sobre lo que escribí, sin poder preguntarme nada adicional.
