# SYN-Flood-CABASE
Análisis técnico y mitigación de una vulnerabilidad DoS (SYN Flood) en Route Servers de infraestructura crítica. Detalla el diagnóstico del colapso del plano de control BGP y la solución definitiva implementada en caliente mediante la configuración de SYN Cookies y políticas de Rate Limiting para garantizar la resiliencia de la red.

# Mitigación de Vulnerabilidades DoS en Route Servers: Caso Práctico y Solución

Este repositorio contiene la documentación técnica, los análisis y las directrices de configuración aplicadas para mitigar de forma definitiva un vector de denegación de servicio (DoS) por inundación de paquetes SYN (**SYN Flood**) en entornos de infraestructura de enrutamiento crítica.

---

## 👁️ El Contexto del Incidente

Durante una auditoría programada y bajo un entorno estrictamente controlado, se analizó el impacto de un flujo masivo de peticiones de conexión dirigidas hacia los componentes centrales de intercambio de tráfico: los **Route Servers**.

### El Escenario Original
*   **Vector:** Un flujo elevado de tráfico `SYN` originado desde un punto de la red interconectada (LINKEAR).
*   **Impacto Inicial:** Los Route Servers no contaban con políticas de mitigación específicas en el stack de red para este tipo de saturación por volumen de conexiones semiabiertas.
*   **Consecuencia Crítica:** El agotamiento de recursos del sistema provocó el colapso de los Route Servers, forzando la desconexión en cadena de todos los *peers* de la red debido a la pérdida de Keepalives BGP. Un escenario sumamente grave para la estabilidad del plano de control.

---

## 🛠️ El Diagnóstico Técnico

El ataque de **SYN Flood** explota el saludo de tres vías de TCP (*Three-Way Handshake*). El origen envía ráfagas de paquetes `SYN`, el servidor responde con `SYN-ACK` y reserva recursos en memoria (la tabla de conexiones *Half-Open*) esperando el `ACK` final, el cual nunca llega. 

Cuando la tabla se llena, el servidor rechaza cualquier nueva conexión, incluyendo las sesiones legítimas de BGP de los operadores conectados.

---

## 🎩 La Solución y Mitigación Implementada

Para resolver esta vulnerabilidad de forma definitiva en caliente y asegurar que la red resistiera futuras anomalías, se aplicaron dos contramedidas fundamentales directamente en el sistema de los Route Servers:

### 1. Activación de SYN Cookies
La solución más efectiva contra el agotamiento de memoria por conexiones semiabiertas es habilitar **SYN Cookies**. Con esto, el servidor no reserva espacio en la tabla de conexiones al recibir un `SYN`. En su lugar, codifica la información de la conexión en el propio número de secuencia del paquete `SYN-ACK`. La memoria solo se asigna si el cliente responde con un `ACK` válido.

En entornos basados en Linux, esto se asegura aplicando y recargando la configuración del núcleo (`/etc/sysctl.conf`):

```ini
# Habilitar la protección TCP SYN Cookies
net.ipv4.tcp_syncookies = 1

# Optimizar el tamaño de la cola de conexiones semiabiertas
net.ipv4.tcp_max_syn_backlog = 2048

```

### 2. Configuración de Rate Limiting (Límite de Flujos)
Para evitar que el volumen puro de paquetes por segundo (pps) sature el stack de procesamiento antes de que actúen las SYN Cookies, se definieron reglas de filtrado y limitación de tasa de transferencia. El objetivo es descartar el exceso de tráfico SYN que supere los umbrales normales de operación.

Ejemplo conceptual utilizando políticas de filtrado del sistema (`iptables`):

```bash
# Limitar las conexiones SYN por segundo por IP de origen para evitar el flood
iptables -A INPUT -p tcp --syn -m limit --limit 50/s --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

```

## 🤓 Conclusión de la Prueba de Resiliencia

 Una vez aplicadas las configuraciones de **SYN Cookies** y **Rate Limiting** en los Route Servers, se volvieron a correr las pruebas de carga en el entorno controlado. 
 
 **Resultado:** Los servidores procesaron el tráfico legítimo sin alteraciones, el uso de recursos y CPU se mantuvo dentro de los parámetros operativos normales y **la red no volvió a caer**. La resiliencia del plano de control quedó garantizada.

## ⚠️ Descargo de Responsabilidad / Disclaimer

Las configuraciones, escenarios y análisis descritos en este repositorio se realizaron bajo autorización expresa, en ventanas de mantenimiento controladas y con el único propósito de mejorar la postura de seguridad, resiliencia y parches de infraestructura del operador. No se fomenta, facilita ni provee software para el uso malicioso de estas técnicas.
