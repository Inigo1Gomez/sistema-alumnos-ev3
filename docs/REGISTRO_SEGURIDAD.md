# Registro de seguridad · Sistema Alumnos

Estudiante: Iñigo Gómez   Repositorio: https://github.com/Inigo1Gomez/sistema-alumnos-ev3   Fecha: 2026-11-27

Cada fila se puede seguir hasta un **build de Jenkins** y un **commit** (identificador `VULN-xx` en el mensaje).
Builds del job `sistema-alumnos`: #1 pipeline base · #2 etapas de seguridad · #3 re-ejecución del mismo commit (sin cambios) ·
#4 VULN-01 · #5 VULN-02 a VULN-04 · #6 VULN-05 a VULN-07 · #7 Dependabot · #8 PR de Dependabot fusionado
(primer build en verde con seguridad completa) · #9 documentación final.

## 1. Revisiones de seguridad realizadas

| # | Etapa del SDLC | Herramienta / técnica | Build | Resultado (resumen) |
|---|---|---|---|---|
| R1 | Código (SAST) | Bandit 1.8.6 en la etapa `Security Review (SAST)` | #2 → #5 | Build #2: **2 High / 2 Medium / 1 Low** (B324 MD5, B201 debug, B608 SQL, B104 bind 0.0.0.0, B105 secreto). Desde el build #5: **0 / 0 / 0** |
| R2 | Dependencias (SCA) | pip-audit 2.9.0 en la etapa `Dependency Management` | #2 → #8 | Build #2: **19 vulnerabilidades en 4 paquetes** (Flask, Werkzeug, Jinja2, gunicorn). Build #8: **0** |
| R3 | Pruebas dinámicas (DAST) | OWASP ZAP 2.16.1 (spider + pasivo + activo) sobre staging (puerto 5001) | #2 → #6 | Build #2: **3 High / 3 Medium / 1 Low**. Build #5: 0 / 3 / 1. Desde el build #6: **0 / 0 / 0** (solo 2 informativas) |
| R4 | Revisión manual | Lectura de `app.py` + `scripts/simular_ataque.py` contra el laboratorio | — | Confirmó SQLi (expone `sqlite_master`), XSS reflejado, clave `admin`/`admin` (MD5 sin sal), sin límite de intentos, sin CSRF, sin cabeceras de seguridad, logs inyectables |
| R5 | Producción | Grafana + Prometheus (dashboard "Sistema Alumnos - Producción (Seguridad)" + 2 reglas de alerta) | — | Incidente a las 18:40: fuerza bruta exitosa, SQLi y XSS contra la versión 1.0.1. Tras la corrección (19:20): 26 intentos bloqueados con HTTP 429 |

## 2. Vulnerabilidades identificadas y corregidas

| ID | Vulnerabilidad (CWE) | Detectada por | Ubicación (código original) | Riesgo | Corrección aplicada | Commit | Build que lo verifica |
|---|---|---|---|---|---|---|---|
| VULN-01 | Inyección SQL (CWE-89) + divulgación del error y de la consulta SQL (CWE-209) | Bandit B608, OWASP ZAP (High), revisión manual, `simular_ataque.py` | `app.py:205-209` (`/alumnos/buscar`) | Alto | Consulta parametrizada (`LIKE ? ESCAPE`), comodines escapados, largo máximo 100, error genérico al cliente y detalle solo en el log | `80d3dc8` | #4 |
| VULN-02 | XSS reflejado y basado en DOM (CWE-79) | OWASP ZAP (2 High), revisión manual | `app.py:153-154` (`/hello`) | Alto | Codificación de salida con `markupsafe.escape` y largo máximo | `8a12397` | #5 (ZAP sin alertas High) |
| VULN-03 | Secretos y credenciales en el código (CWE-798/CWE-259), MD5 sin sal (CWE-327/CWE-916), clave por defecto `admin` (CWE-521) | Bandit B105 y B324, revisión manual | `app.py:20-23`, `app.py:221` | Alto | `SECRET_KEY` y credenciales desde variables de entorno; hash scrypt/PBKDF2 con sal (`check_password_hash`); sin `ADMIN_CLAVE_HASH` el login queda deshabilitado; comparación en tiempo constante | `8276977` | #5 |
| VULN-04 | Depurador de Flask activo (ejecución remota de código, CWE-94/CWE-489) y escucha en todas las interfaces (CWE-605) | Bandit B201 y B104 | `app.py:241` | Alto | `debug=False`, host `127.0.0.1` por defecto (producción usa gunicorn) | `4602295` | #5 (Bandit 0/0/0) |
| VULN-05 | Sin protección contra fuerza bruta (CWE-307) + inyección en logs (CWE-117) | Grafana (alerta "Fuerza bruta en login") y `simular_ataque.py` | `app.py:213-226` (`/login`) | Alto | Máximo 5 fallos por IP cada 5 min → HTTP 429 con `Retry-After`; nueva métrica `login_bloqueados_total`; usuario saneado antes de escribirlo en el log | `8e98799` | #6; verificado en producción con el build #8 (26 de 31 intentos bloqueados) |
| VULN-06 | Ausencia de token anti-CSRF (CWE-352) | OWASP ZAP (Medium) | `app.py:69-72` (formulario) y `/login` | Medio | Token aleatorio por sesión en campo oculto `csrf_token`, validado con `secrets.compare_digest` (HTTP 400 si falta) | `8759393` | #6 |
| VULN-07 | Cabeceras de seguridad ausentes: CSP, anti-clickjacking, nosniff (CWE-693, CWE-1021); cookie sin SameSite | OWASP ZAP (2 Medium, 1 Low) | `app.py:124-135` (todas las respuestas) | Medio | CSP restrictiva, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, Referrer/Permissions-Policy, COOP/CORP/COEP, `Cache-Control: no-store`; cookie `HttpOnly` + `SameSite=Strict` | `558edb8` | #6 (ZAP 0/0/0) |
| VULN-08 | Componentes con vulnerabilidades conocidas (CWE-1395) | pip-audit, Dependabot | `requirements.txt` | Alto | Dependabot configurado (`.github/dependabot.yml`) y PR #1 agrupado con todas las dependencias a su última versión | `55f6d37` + PR #1 (merge `2b58215`) | #8 (pip-audit 0) |

## 3. Resultados de OWASP ZAP

Escaneo del build #2 sobre staging (`http://jenkins:5001`).

| Alerta de ZAP | Riesgo | URL de ejemplo | VULN relacionada | Cómo se mitiga | ¿Mitigada? Build |
|---|---|---|---|---|---|
| SQL Injection | High | `/alumnos/buscar?nombre='` | VULN-01 | Consulta parametrizada y error genérico | Sí · #4 |
| Cross Site Scripting (Reflected) | High | `/hello?name=</h1><scrIpt>alert(1);</scRipt><h1>` | VULN-02 | Escapar la salida HTML (`escape`) + CSP | Sí · #5 |
| Cross Site Scripting (DOM Based) | High | `/hello?name=<script>alert(5397)</script>` | VULN-02 | Escapar la salida HTML (`escape`) + CSP | Sí · #5 |
| Absence of Anti-CSRF Tokens | Medium | `/` (formulario de login) | VULN-06 | Token anti-CSRF por sesión validado en `/login` | Sí · #6 |
| Content Security Policy (CSP) Header Not Set | Medium | `/`, `/alumnos`, `/hello` | VULN-07 | Cabecera `Content-Security-Policy` en todas las respuestas | Sí · #6 |
| Missing Anti-clickjacking Header | Medium | `/` | VULN-07 | `X-Frame-Options: DENY` + `frame-ancestors 'none'` | Sí · #6 |
| X-Content-Type-Options Header Missing | Low | `/`, `/alumnos`, `/health` | VULN-07 | `X-Content-Type-Options: nosniff` | Sí · #6 |
| Session Management Response Identified / User Agent Fuzzer | Informational | `/` | — | Informativas, no son vulnerabilidades | No requiere |

Evolución (High/Medium/Low): #2 3/3/1 → #5 0/3/1 → **#6 0/0/0**. La inyección SQL la detectaron Bandit, ZAP y la revisión manual;
el XSS y la falta de cabeceras solo ZAP. Por eso el pipeline combina SAST, SCA, DAST y revisión manual.

## 4. Monitoreo e incidentes

Fuente de datos Prometheus (`http://prometheus:9090`, raspa `jenkins:5000` cada 5 s) · Dashboard "Sistema Alumnos - Producción (Seguridad)" ·
Reglas: **Fuerza bruta en login** (`sum(increase(login_fallidos_total{job="produccion"}[1m])) > 5`) y
**Peticiones sospechosas** (`sum(increase(peticiones_sospechosas_total{job="produccion"}[2m])) > 0`), evaluadas cada 10 s.

| Hora | Panel / métrica de Grafana | Qué se observó | Entorno | Clasificación | Acción de respuesta | Verificación |
|---|---|---|---|---|---|---|
| 18:40 | Logins fallidos por minuto (`login_fallidos_total`) + alerta "Fuerza bruta en login" en Firing desde las 18:40:00 | Dos ataques seguidos: ~60 logins fallidos en 5 min desde una misma IP y 2 logins exitosos; la clave `admin` fue adivinada | Producción 1.0.1+98718a4 | Incidente **crítico**: fuerza bruta exitosa, cuenta de administrador comprometida (CWE-307, CWE-521) | Contención: el gate impide desplegar builds con hallazgos. Erradicación: VULN-03 (clave por defecto eliminada, hash fuerte) y VULN-05 (límite de intentos, 429). Recuperación: despliegue del build #8 | 19:20, ataque repetido contra 1.0.8+2b58215: ninguna clave funcionó, 26 de 31 intentos con HTTP 429, 0 logins exitosos |
| 18:40 | Peticiones sospechosas por tipo (`peticiones_sospechosas_total{tipo}`) + alerta "Peticiones sospechosas" en Firing desde las 18:40:30 | Intentos de `sqli` y `xss`; la SQLi devolvió la estructura de la base (`sqlite_master`) y el script se reflejó en `/hello` | Producción 1.0.1+98718a4 | Incidente **alto**: intento de exfiltración (SQLi) y XSS reflejado | VULN-01 (consulta parametrizada) y VULN-02 (escape de salida) desplegados con el build #8 | 19:20: la SQLi no devuelve datos internos y el XSS sale escapado; el contador sigue detectando los intentos |
| 19:17 | Versión desplegada (`app_info{version}`) | Cambio de 1.0.1+98718a4 a 1.0.8+2b58215 | Producción | Cambio planificado | Despliegue automático del pipeline (solo build en verde) | El panel y `/version` muestran 1.0.8+2b58215 |

## 5. Gestión de dependencias

Proceso: pip-audit en cada build (bloquea producción si hay CVE) → Dependabot (`.github/dependabot.yml`, ecosistema pip, revisión diaria,
actualizaciones **agrupadas** en un solo PR porque Flask/Werkzeug/Jinja2 dependen entre sí) → revisión del PR #1 → fusión en `main`
(merge `2b58215`) → Jenkins vuelve a correr pruebas, Bandit, pip-audit y ZAP → producción solo si todo queda en verde (build #8).

| Paquete | Versión inicial | Vulnerabilidades (IDs) | Versión final | Origen del cambio (PR de Dependabot / manual) | ¿Pruebas, pip-audit y ZAP siguen OK? Build |
|---|---|---|---|---|---|
| Flask | 2.2.2 | CVE-2023-30861, CVE-2026-27205 | 3.1.3 | PR de Dependabot #1 (grupo `dependencias-python`) | Sí: 9/9, 0 vuln., ZAP 0/0/0 · #8 |
| Werkzeug | 2.2.2 | CVE-2023-25577, CVE-2023-23934, CVE-2023-46136, CVE-2024-34069, CVE-2024-49766, CVE-2024-49767, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, CVE-2026-102598 | 3.1.9 | PR de Dependabot #1 | Sí · #8 |
| Jinja2 | 3.1.2 | CVE-2024-22195, CVE-2024-34064, CVE-2024-56201, CVE-2024-56326, CVE-2025-27516 | 3.1.6 | PR de Dependabot #1 | Sí · #8 |
| gunicorn | 21.2.0 | CVE-2024-1135, CVE-2024-6827 | 27.0.1 | PR de Dependabot #1 | Sí · #8 |
| prometheus-client | 0.17.1 | Ninguna | 0.26.0 | PR de Dependabot #1 (versión al día) | Sí · #8 |
| pytest (solo pruebas) | 8.3.4 | Ninguna | 9.2.0 | PR de Dependabot #1 | Sí · #8 |

## 6. Trazabilidad

El `TRAZABILIDAD.md` del último build (artefacto de Jenkins) contiene una fila por build: versión, commit, pruebas,
Bandit H/M/L, pip-audit, ZAP H/M/L, resultado y versión en producción.

| Actividad | Hallazgo | Build que lo detectó | Commit / PR que lo resolvió | Build que lo verificó | Versión en producción |
|---|---|---|---|---|---|
| Revisión de seguridad (Bandit) | B608 inyección SQL en `/alumnos/buscar` (VULN-01) | #2 | `80d3dc8` VULN-01 | #4 | 1.0.8+2b58215 |
| Revisión de seguridad (Bandit) | B324 MD5 y B201 debug (VULN-03, VULN-04) | #2 | `8276977` VULN-03 · `4602295` VULN-04 | #5 (0/0/0) | 1.0.8+2b58215 |
| Prueba automatizada (OWASP ZAP) | SQLi y XSS en `/alumnos/buscar` y `/hello` (VULN-01, VULN-02) | #2 | `80d3dc8` VULN-01 · `8a12397` VULN-02 | #5 (sin High) | 1.0.8+2b58215 |
| Prueba automatizada (OWASP ZAP) | Falta CSRF y cabeceras (VULN-06, VULN-07) | #2 | `8759393` VULN-06 · `558edb8` VULN-07 | #6 (0/0/0) | 1.0.8+2b58215 |
| Gestión de dependencias (Dependabot) | 19 CVE en Flask, Werkzeug, Jinja2 y gunicorn (VULN-08) | #2 | `55f6d37` + PR #1 (merge `2b58215`) | #8 (0 vuln.) | 1.0.8+2b58215 |
| Monitoreo (Grafana) | Fuerza bruta exitosa en producción (VULN-05) | Alerta en producción 1.0.1 (18:40) | `8e98799` VULN-05 | #6 y ataque repetido sobre #8 (19:20) | 1.0.8+2b58215 |