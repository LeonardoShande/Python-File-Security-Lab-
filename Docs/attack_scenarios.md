# Escenarios de ataque simulados

Todos los escenarios descritos aquí se ejecutan **exclusivamente**
contra archivos creados por el propio laboratorio dentro de `lab/`.
Ninguno de estos flujos accede a la red, a archivos fuera de `lab/`,
ni a sistemas de terceros.

## Escenario 1 — Contraseña débil + ataque de diccionario

**Objetivo educativo:** mostrar cuán rápido cae una contraseña común.

**Pasos (automatizados en `vuln-demo` / opción [3] del menú):**

1. Se crea `lab/original/weak_demo.txt`.
2. Se cifra con AES-256-GCM usando la passphrase `"123456"`
   (`vulnerability_lab.run_weak_password_demo`).
3. Se ejecuta `dictionary_attack`, que prueba secuencialmente un
   diccionario corto de 10 contraseñas comunes
   (`123456`, `password`, `qwerty`, `letmein`, `admin`, `111111`,
   `abc123`, `iloveyou`, `welcome`, `1234`).
4. Cada intento llama a `decryption.try_decrypt`, que intenta
   descifrar en memoria y usa el tag de autenticación GCM como
   oráculo de éxito/fallo.

**Resultado esperado:** la contraseña se encuentra en el primer
intento, demostrando que una passphrase de diccionario común ofrece
prácticamente cero resistencia, sin importar cuán fuerte sea el
algoritmo de cifrado subyacente.

**Contraste:** si se repite el mismo flujo manualmente con
`encrypt_file` usando una passphrase larga y aleatoria (opción [1]),
el mismo diccionario de 10 palabras no encuentra ninguna coincidencia.

## Escenario 2 — Algoritmos de hash obsoletos

**Objetivo educativo:** visualizar la diferencia entre MD5/SHA-1 y
SHA-256.

**Pasos (`report` / opción [6] del menú):**

1. Se calculan MD5, SHA-1 y SHA-256 del mismo archivo
   (`vulnerability_lab.legacy_hash_comparison`).
2. Se imprime un informe comparativo con una explicación de por qué
   MD5 y SHA-1 están rotos criptográficamente (ver
   `docs/security_analysis.md` para los detalles técnicos y
   referencias).

## Escenario 3 — Detección de manipulación (tampering)

**Objetivo educativo:** demostrar que un archivo cifrado y/o
verificado con hash no puede alterarse sin ser detectado.

**Pasos:**

1. Se protege un archivo (Escenario A): se obtiene su hash SHA-256 y
   se cifra con AES-256-GCM.
2. `vulnerability_lab.simulate_tamper` copia el archivo cifrado a
   `lab/modified/` e invierte un byte del texto cifrado.
3. Se intenta descifrar el archivo modificado
   (`decryption.try_decrypt`): la operación falla porque el tag de
   autenticación GCM ya no coincide.
4. Si en cambio se compara el hash SHA-256 del archivo *original* (sin
   cifrar) tras una modificación directa, `integrity.verify_file`
   reporta el estado `MODIFIED`.

**Resultado esperado:** en ambos casos (cifrado alterado o archivo
plano alterado), el laboratorio detecta la manipulación de forma
explícita, nunca silenciosa.

## Qué NO hace este laboratorio (límites explícitos)

- No ataca archivos, cuentas o sistemas fuera de `lab/`.
- No implementa fuerza bruta distribuida, paralela ni contra sistemas
  remotos.
- No incluye ransomware, keyloggers, exfiltración de datos ni
  mecanismos de persistencia.
- No acepta diccionarios de contraseñas arbitrarios apuntando a rutas
  externas (el guard `_require_lab_path` lo impide).
- No debe usarse, bajo ninguna circunstancia, contra sistemas o datos
  sin autorización explícita del propietario.
