¡Claro! Aquí tienes una descripción concisa para el repositorio de GitHub y un archivo `README.md` completo y bien estructurado para el proyecto.

---

### Descripción para el Repositorio de GitHub

**Herramienta de línea de comandos en Python para cifrado y descifrado AES-128-CBC, compatible con el formato de OpenSSL `enc`.**

---

### Archivo README.md

```markdown
# xaes.py - Cifrado AES compatible con OpenSSL

`xaes.py` es una sencilla herramienta de línea de comandos escrita en Python 3 para cifrar y descifrar datos utilizando el algoritmo AES. Está diseñada para ser un reemplazo o complemento simple y multiplataforma para el comando `openssl enc`, generando un formato de salida idéntico.

La herramienta lee datos de la entrada estándar (`stdin`) y escribe el resultado en la salida estándar (`stdout`), lo que permite integrarla fácilmente en pipelines de comandos.

## Características Principales

-   **Cifrado y Descifrado:** Soporta ambas operaciones a través de los flags `-e` y `-d`.
-   **Algoritmo Robusto:** Utiliza AES-128 en modo CBC (Cipher Block Chaining).
-   **Derivación de Clave Segura:** Genera la clave de cifrado y el vector de inicialización (IV) a partir de una contraseña usando PBKDF2 con SHA256 y 10,000 iteraciones.
-   **Formato Compatible con OpenSSL:** Los archivos cifrados por esta herramienta pueden ser descifrados con `openssl enc -d -aes-128-cbc` y viceversa. Utiliza la cabecera estándar `Salted__` seguida de una sal (salt) de 8 bytes.
-   **Uso Sencillo:** Interfaz simple y directa, ideal para scripts y automatización.
-   **Autocontenido:** Solo depende de la biblioteca `pycryptodome`.

## Requisitos

-   Python 3.6+
-   La biblioteca `pycryptodome`.

Puedes instalar la dependencia necesaria usando pip:
```sh
pip install pycryptodome
```

## Uso

El script se invoca con dos argumentos: un modo de operación (`-e` para cifrar o `-d` para descifrar) y la contraseña.

### Cifrar

Para cifrar un archivo, puedes redirigir su contenido a la entrada estándar del script.

```sh
# Cifrar el contenido de 'mi_secreto.txt' y guardarlo en 'mi_secreto.enc'
cat mi_secreto.txt | ./xaes.py -e "mi_contraseña_segura" > mi_secreto.enc
```

También puedes cifrar texto directamente:
```sh
echo "Este es un mensaje secreto" | ./xaes.py -e "mi_contraseña_segura" > mensaje.enc
```

### Descifrar

Para descifrar, el proceso es el inverso.

```sh
# Descifrar 'mi_secreto.enc' y mostrar el resultado en la terminal
cat mi_secreto.enc | ./xaes.py -d "mi_contraseña_segura"

# Descifrar 'mi_secreto.enc' y guardarlo en un nuevo archivo
cat mi_secreto.enc | ./xaes.py -d "mi_contraseña_segura" > mi_secreto_descifrado.txt
```

## Compatibilidad con OpenSSL

La principal ventaja de esta herramienta es su interoperabilidad con OpenSSL.

#### Cifrar con `xaes.py` y descifrar con `openssl`

```sh
# 1. Cifrar con xaes.py
echo "Hola OpenSSL" | ./xaes.py -e "password123" > hola.enc

# 2. Descifrar el mismo archivo con openssl
openssl enc -d -aes-128-cbc -in hola.enc -k "password123"
# Salida esperada: Hola OpenSSL
```

#### Cifrar con `openssl` y descifrar con `xaes.py`

```sh
# 1. Cifrar con openssl (asegúrate de usar -salt para que el formato coincida)
openssl enc -e -aes-128-cbc -salt -in mi_archivo.txt -out mi_archivo.openssl.enc -k "password123"

# 2. Descifrar el archivo generado con xaes.py
cat mi_archivo.openssl.enc | ./xaes.py -d "password123"
```

## Detalles Técnicos

La implementación sigue las convenciones de OpenSSL para la derivación de claves a partir de contraseñas:

-   **Algoritmo:** AES
-   **Tamaño de clave:** 128 bits (16 bytes)
-   **Modo de operación:** CBC (Cipher Block Chaining)
-   **Vector de Inicialización (IV):** 128 bits (16 bytes)
-   **Relleno (Padding):** PKCS7
-   **Función de Derivación de Clave (KDF):** PBKDF2
-   **Hash para KDF:** HMAC-SHA256
-   **Iteraciones de PBKDF2:** 10,000
-   **Sal (Salt):** 64 bits (8 bytes), generada aleatoriamente para cada cifrado y prefijada al texto cifrado.

## Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.
```
