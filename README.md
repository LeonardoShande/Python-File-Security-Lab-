# File Security Lab

Laboratorio educativo en Python para demostrar, en un entorno
controlado, cómo se protege un archivo con criptografía moderna
(AES-256-GCM + SHA-256) y cómo pueden explotarse mecanismos de
protección débiles (contraseñas comunes, algoritmos de hash
obsoletos como MD5/SHA-1).

> **Uso exclusivamente educativo.** Todas las operaciones de
> "vulnerabilidad" se ejecutan únicamente contra archivos que el
> propio laboratorio crea dentro de `lab/`. Nunca se accede a la red
> ni a archivos fuera de ese sandbox. Ver [Seguridad y
> restricciones](#seguridad-y-restricciones).

## Índice

- [Objetivo del proyecto](#objetivo-del-proyecto)
- [Arquitectura](#arquitectura)
- [Instalación](#instalación)
- [Uso — menú interactivo](#uso--menú-interactivo)
- [Uso — línea de comandos](#uso--línea-de-comandos)
- [Módulos](#módulos)
- [Tests](#tests)
- [Seguridad y restricciones](#seguridad-y-restricciones)
- [Documentación adicional](#documentación-adicional)

## Objetivo del proyecto

El laboratorio cubre dos escenarios:

**Escenario A — Protección de archivos**
Cálculo de hash SHA-256, cifrado AES-256-GCM, derivación de clave con
Scrypt, verificación de integridad, detección de modificaciones y
descifrado con la clave correcta.

**Escenario B — Análisis de vulnerabilidades**
Simulación de un archivo protegido con una contraseña débil, ataque
de diccionario controlado (contra archivos propios del laboratorio),
comparación MD5/SHA-1 vs SHA-256, y detección de manipulación.

## Arquitectura

```
file-security-lab/
├── README.md
├── requirements.txt
├── LICENSE
├── .gitignore
├── src/
│   ├── encryption.py        # AES-256-GCM + derivación de clave (Scrypt)
│   ├── hashing.py            # SHA-256 (real) y MD5/SHA-1 (educativo)
│   ├── integrity.py          # Manifiesto JSON + verificación de integridad
│   ├── decryption.py         # Descifrado autenticado
│   ├── vulnerability_lab.py  # Escenario B, confinado a lab/
│   └── main.py                # CLI (menú interactivo + argparse)
├── lab/
│   ├── original/              # Archivos de prueba sin proteger
│   ├── protected/              # Archivos cifrados (.fslb) + manifest.json
│   └── modified/               # Copias alteradas para demostrar detección
├── tests/
│   ├── test_encryption.py
│   ├── test_hashing.py
│   ├── test_integrity.py
│   └── test_vulnerability_lab.py
├── docs/
│   ├── architecture.md
│   ├── security_analysis.md
│   └── attack_scenarios.md
└── .github/workflows/python-tests.yml
```

Ver [`docs/architecture.md`](docs/architecture.md) para un diagrama de
flujo de datos entre módulos y las decisiones de diseño (por qué
AES-GCM, por qué Scrypt, etc.).

## Instalación

```bash
git clone <tu-fork>/file-security-lab.git
cd file-security-lab
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Requiere Python 3.10+.

## Uso — menú interactivo

```bash
python -m src.main
```

```
======================================================================
  FILE SECURITY LAB  -  Python Educational Cybersecurity Laboratory
  Scenario A: Protection (AES-256-GCM + SHA-256)
  Scenario B: Vulnerability analysis (weak passwords, legacy hashes)
  All operations are confined to the lab/ sandbox directory.
======================================================================

[1] Proteger archivo
[2] Analizar integridad
[3] Simular vulnerabilidad
[4] Ejecutar prueba de contrasena
[5] Descifrar archivo
[6] Generar informe de seguridad
[0] Salir
```

- **[1] Proteger archivo**: pide una ruta (crea un archivo de prueba
  si no existe) y una passphrase; calcula su SHA-256, lo cifra con
  AES-256-GCM y guarda un registro de integridad.
- **[2] Analizar integridad**: compara el hash actual de un archivo
  contra el valor registrado al protegerlo.
- **[3] Simular vulnerabilidad**: ejecuta el flujo completo del
  Escenario B (passphrase débil + ataque de diccionario +
  simulación de manipulación).
- **[4] Ejecutar prueba de contraseña**: corre el diccionario de
  demostración contra un archivo `.fslb` existente dentro de `lab/`.
- **[5] Descifrar archivo**: descifra un `.fslb` con la passphrase
  correcta (o reporta fallo si es incorrecta o el archivo fue
  alterado).
- **[6] Generar informe de seguridad**: compara MD5, SHA-1 y SHA-256
  del mismo archivo con una breve explicación de cada uno.

## Uso — línea de comandos

Todas las acciones también están disponibles de forma no interactiva
(útil para scripts o CI):

```bash
# Proteger un archivo
python -m src.main protect --file lab/original/sample.txt --password "Fr4se-Larga-Y-Aleatoria!"

# Verificar integridad
python -m src.main integrity --file lab/original/sample.txt

# Ejecutar la demo completa de vulnerabilidades (crea su propio archivo débil)
python -m src.main vuln-demo

# Probar el diccionario de demo contra un .fslb existente en lab/
python -m src.main password-test --file lab/protected/weak_demo.fslb

# Descifrar
python -m src.main decrypt --file lab/protected/sample.fslb --password "Fr4se-Larga-Y-Aleatoria!"

# Informe de hashes
python -m src.main report --file lab/original/sample.txt
```

## Módulos

| Módulo                  | Responsabilidad                                                                 |
|--------------------------|----------------------------------------------------------------------------------|
| `hashing.py`             | SHA-256 (uso real) y MD5/SHA-1 (solo comparación educativa). Streaming por chunks. |
| `encryption.py`          | Derivación de clave con Scrypt + cifrado AES-256-GCM. Formato de contenedor `.fslb`. |
| `decryption.py`          | Descifrado autenticado; distingue errores de contraseña/manipulación.            |
| `integrity.py`           | Manifiesto JSON de hashes SHA-256; verificación INTACT/MODIFIED/MISSING.          |
| `vulnerability_lab.py`   | Escenario B completo, confinado a `lab/` mediante `_require_lab_path`.            |
| `main.py`                | CLI: menú interactivo y subcomandos `argparse`.                                   |

## Tests

```bash
pytest tests/ -v
```

21 pruebas cubren: cifrado/descifrado correcto, rechazo de contraseña
incorrecta, detección de manipulación vía GCM, manejo de errores,
manifiesto de integridad (INTACT/MODIFIED/MISSING), el flujo completo
de la demo de contraseña débil, y el guardrail de sandbox de
`vulnerability_lab.py`.

GitHub Actions (`.github/workflows/python-tests.yml`) ejecuta la
suite en Python 3.10, 3.11 y 3.12 en cada push/PR a `main`, además de
un smoke test del CLI completo.

## Seguridad y restricciones

- Todas las operaciones del Escenario B están confinadas a `lab/`
  mediante un guard explícito (`LabPathError` si se intenta operar
  fuera de esa carpeta).
- El diccionario de contraseñas es corto, fijo y embebido — no es una
  herramienta de cracking general ni acepta wordlists externas
  apuntando fuera del sandbox.
- No se almacenan claves ni contraseñas en el repositorio; solo sales
  y parámetros de KDF (no secretos) dentro de los contenedores
  `.fslb`.
- No hay acceso a red, persistencia, ni mecanismos tipo ransomware.
- Ningún archivo real del sistema operativo es modificado: el
  laboratorio solo lee/escribe dentro de `lab/`.

## Documentación adicional

- [`docs/architecture.md`](docs/architecture.md) — diagrama de
  arquitectura y decisiones de diseño (AES-GCM vs CBC, Scrypt, etc.).
- [`docs/security_analysis.md`](docs/security_analysis.md) — análisis
  de cada algoritmo, riesgos de contraseñas débiles y mitigaciones.
- [`docs/attack_scenarios.md`](docs/attack_scenarios.md) — descripción
  paso a paso de cada escenario de ataque simulado y sus límites
  explícitos.

## Licencia

MIT — ver [`LICENSE`](LICENSE). Incluye un aviso adicional de uso
educativo para las funciones de análisis de vulnerabilidades.
