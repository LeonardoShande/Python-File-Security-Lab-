# Arquitectura — File Security Lab

## Visión general

El proyecto se organiza en módulos independientes dentro de `src/`, cada
uno con una única responsabilidad. El punto de entrada (`main.py`) orquesta
las llamadas a estos módulos desde un menú de terminal o desde argumentos
de línea de comandos (`argparse`).

```
┌─────────────────────────────────────────────────────────────────┐
│                           main.py (CLI)                         │
│     Menú interactivo  /  argparse (protect, integrity, ...)     │
└───────┬───────────┬────────────┬────────────┬───────────────────┘
        │            │            │            │
        ▼            ▼            ▼            ▼
   hashing.py   encryption.py  integrity.py  vulnerability_lab.py
        ▲            │              ▲               │
        │            ▼              │               ▼
        │      decryption.py────────┘        (usa encryption.py,
        │                                       decryption.py,
        └───────────────────────────────────────hashing.py)
```

## Flujo — Escenario A (Protección)

1. `main.py` calcula el hash SHA-256 original con `hashing.sha256_file`.
2. `encryption.encrypt_file` deriva una clave AES-256 desde la
   passphrase del usuario usando **Scrypt** (KDF lenta, con sal
   aleatoria), y cifra el archivo con **AES-256-GCM**, que es un modo
   *autenticado*: cualquier modificación del texto cifrado será
   detectada en el descifrado.
3. El resultado se guarda como un contenedor binario `.fslb` que
   incluye: cabecera mágica, versión, parámetros de Scrypt, sal (16
   bytes), nonce (12 bytes) y el texto cifrado (con su tag GCM).
4. `integrity.add_file_to_manifest` registra el hash SHA-256 original
   en `lab/protected/manifest.json`, para verificaciones futuras.

## Flujo — Escenario B (Vulnerabilidades)

1. `vulnerability_lab.run_weak_password_demo` crea **su propio**
   archivo de laboratorio y lo cifra con una passphrase débil
   conocida (p. ej. `"123456"`), usando el mismo formato `.fslb`.
2. `vulnerability_lab.dictionary_attack` prueba un diccionario corto
   y embebido de contraseñas comunes, usando `decryption.try_decrypt`
   (que intenta descifrar en memoria y reporta éxito/fallo mediante
   el tag de autenticación GCM).
3. `vulnerability_lab.legacy_hash_comparison` calcula MD5, SHA-1 y
   SHA-256 del mismo archivo y explica por qué MD5/SHA-1 ya no son
   apropiados para integridad o seguridad.
4. `vulnerability_lab.simulate_tamper` copia un archivo protegido,
   invierte un byte del texto cifrado, y demuestra cómo tanto el hash
   SHA-256 como la autenticación GCM detectan la alteración.

## Barreras de seguridad (guardrails)

- `vulnerability_lab._require_lab_path` impide operar fuera de
  `lab/`: cualquier intento de apuntar a una ruta externa lanza
  `LabPathError`.
- El diccionario de contraseñas es corto, fijo y solo se usa contra
  archivos que el propio módulo generó en la misma sesión.
- No hay acceso a red, no hay persistencia, no hay escalado de
  privilegios: el proyecto solo lee/escribe dentro de `lab/`.
- Claves y contraseñas nunca se escriben en disco; solo se derivan en
  memoria a partir de la sal almacenada y la passphrase que el
  usuario reintroduce.

## Por qué AES-256-GCM y no AES-CBC

AES-CBC por sí solo solo ofrece confidencialidad: un atacante puede
alterar el texto cifrado y el descifrado "funcionará" devolviendo
datos corruptos sin ninguna señal de alerta (a menos que se añada un
HMAC por separado, el patrón "Encrypt-then-MAC"). AES-GCM integra la
autenticación: el `tag` de 16 bytes garantiza que cualquier
modificación del texto cifrado o de los datos asociados (AAD) hace
que el descifrado falle explícitamente (`InvalidTag`). Por eso es la
base de la protección "real" en este proyecto.

## Por qué Scrypt para derivar la clave

Una contraseña corta tiene baja entropía. Si derivamos la clave AES
directamente con una función rápida (como SHA-256 simple), un
atacante con GPUs puede probar miles de millones de contraseñas por
segundo. Scrypt es deliberadamente costosa en CPU y memoria, lo que
reduce drásticamente la velocidad de ataque por fuerza bruta o
diccionario, incluso con hardware especializado.
