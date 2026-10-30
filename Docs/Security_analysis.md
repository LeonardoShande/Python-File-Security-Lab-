# Análisis de seguridad

## Algoritmos usados y por qué

| Propósito                     | Algoritmo         | Estado actual                          |
|--------------------------------|--------------------|-----------------------------------------|
| Integridad real (Escenario A)  | SHA-256            | Fuerte, recomendado                     |
| Cifrado real (Escenario A)     | AES-256-GCM        | Fuerte, autenticado, recomendado        |
| Derivación de clave            | Scrypt             | Fuerte, costosa en CPU/memoria          |
| Comparación educativa (Esc. B) | MD5                | **Roto** — colisiones prácticas         |
| Comparación educativa (Esc. B) | SHA-1               | **Roto** — colisión demostrada (2017)   |

## MD5 — por qué no usarlo

MD5 es vulnerable a ataques de colisión práctica desde 2004-2008: es
posible construir dos archivos distintos con el mismo hash MD5 en
cuestión de segundos con hardware moderno. Esto invalida su uso para:

- Verificación de integridad adversarial (un atacante puede modificar
  un archivo manteniendo el mismo hash).
- Firmas digitales o certificados.

Sigue siendo aceptable únicamente como *checksum* no adversarial (por
ejemplo, detectar corrupción accidental de un archivo durante una
transferencia), nunca como control de seguridad.

## SHA-1 — por qué no usarlo

En 2017, Google y CWI Amsterdam publicaron "SHAttered", la primera
colisión práctica de SHA-1 en el mundo real. Desde entonces, NIST y la
mayoría de navegadores/autoridades de certificación han retirado SHA-1
para firmas digitales y certificados TLS. Igual que MD5, no debe
usarse donde un atacante pueda estar interesado en falsificar o
modificar contenido sin ser detectado.

## SHA-256 — por qué sí usarlo

SHA-256 (familia SHA-2) no tiene colisiones conocidas prácticas a la
fecha de este documento y es el estándar de facto para integridad y
huellas digitales en aplicaciones modernas (Git, TLS, blockchain,
firmas de software). Por eso es el único algoritmo que este proyecto
usa en `integrity.py` para verificación real.

## Contraseñas débiles — el riesgo demostrado en Escenario B

El módulo `vulnerability_lab.py` cifra un archivo de laboratorio con
una passphrase deliberadamente débil (p. ej. `"123456"`) y luego
ejecuta un diccionario corto y embebido de contraseñas comunes contra
ese mismo archivo. El resultado típico: la contraseña se encuentra en
el primer intento.

Esto ilustra un principio fundamental: **la seguridad del cifrado
depende tanto del algoritmo como de la calidad de la clave/contraseña**.
AES-256 es matemáticamente robusto, pero si la clave se deriva de
`"123456"`, el eslabón débil es la contraseña, no el cifrado.

### Mitigaciones recomendadas

1. Usar frases de contraseña largas, aleatorias y únicas (gestor de
   contraseñas).
2. Usar una KDF lenta y con costo configurable (Scrypt, Argon2,
   PBKDF2 con iteraciones altas) para encarecer los ataques offline.
3. Añadir autenticación de dos factores donde sea posible.
4. Monitorizar intentos de acceso fallidos cuando el sistema lo
   permita (rate limiting, bloqueo tras N intentos).

## Modificación de archivos y detección

Dos mecanismos independientes detectan alteraciones en este proyecto:

1. **Hash SHA-256 + manifiesto** (`integrity.py`): compara el hash
   actual del archivo contra el valor registrado al momento de
   protegerlo.
2. **Tag de autenticación AES-GCM** (`encryption.py` /
   `decryption.py`): si el contenido cifrado se altera, el descifrado
   falla explícitamente con `InvalidTag`, sin importar si se conoce la
   contraseña correcta.

Tener ambos mecanismos es una buena práctica de defensa en profundidad:
incluso si uno fallara o se omitiera, el otro seguiría detectando la
manipulación.

## Limitaciones conocidas de este laboratorio

- El diccionario de contraseñas es intencionalmente pequeño y fijo;
  no es una herramienta de cracking de propósito general.
- Los parámetros de Scrypt usados en las demos de Escenario B se
  reducen deliberadamente para que el ejercicio sea rápido en clase;
  en producción deben usarse los valores por defecto (o más altos) de
  `encryption.py`.
- Este proyecto no implementa gestión de usuarios, control de acceso
  por roles, ni almacenamiento seguro de contraseñas (KDF de usuario)
  — está enfocado exclusivamente en protección/verificación de
  archivos individuales.
