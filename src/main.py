"""
main.py
=======

Professional terminal interface tying every module together into the
interactive menu described in the project brief:

    [1] Proteger archivo
    [2] Analizar integridad
    [3] Simular vulnerabilidad
    [4] Ejecutar prueba de contraseña
    [5] Descifrar archivo
    [6] Generar informe de seguridad
    [0] Salir

Also exposes an argparse-based non-interactive mode so the lab can be
scripted/tested (e.g. in CI) without manual input:

    python -m src.main protect   --file lab/original/sample.txt --password "Str0ng!Pass"
    python -m src.main integrity --file lab/protected/sample.fslb
    python -m src.main vuln-demo
    python -m src.main decrypt   --file lab/protected/sample.fslb --password "Str0ng!Pass"
    python -m src.main report    --file lab/original/sample.txt

Run with no arguments to get the interactive menu.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import decryption, encryption, hashing, integrity, vulnerability_lab

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LAB_ROOT = PROJECT_ROOT / "lab"
ORIGINAL_DIR = LAB_ROOT / "original"
PROTECTED_DIR = LAB_ROOT / "protected"
MODIFIED_DIR = LAB_ROOT / "modified"
MANIFEST_PATH = PROTECTED_DIR / "manifest.json"

BANNER = r"""
======================================================================
  FILE SECURITY LAB  -  Python Educational Cybersecurity Laboratory
  Scenario A: Protection (AES-256-GCM + SHA-256)
  Scenario B: Vulnerability analysis (weak passwords, legacy hashes)
  All operations are confined to the lab/ sandbox directory.
======================================================================
"""


def _ensure_dirs() -> None:
    for d in (ORIGINAL_DIR, PROTECTED_DIR, MODIFIED_DIR):
        d.mkdir(parents=True, exist_ok=True)


# ----------------------------------------------------------------------
# Action implementations (shared by both interactive menu and argparse)
# ----------------------------------------------------------------------


def action_protect(file_path: Path, password: str) -> None:
    _ensure_dirs()
    if not file_path.is_file():
        print(f"[ERROR] File not found: {file_path}")
        return

    original_hash = hashing.sha256_file(file_path)
    print(f"[INFO] Original SHA-256: {original_hash.hexdigest}")

    dest = PROTECTED_DIR / (file_path.stem + ".fslb")
    encryption.encrypt_file(file_path, dest, password)
    print(f"[OK] File encrypted (AES-256-GCM) -> {dest}")

    manifest = (
        integrity.load_manifest(MANIFEST_PATH)
        if MANIFEST_PATH.is_file()
        else integrity.Manifest()
    )
    integrity.add_file_to_manifest(manifest, file_path)
    integrity.save_manifest(manifest, MANIFEST_PATH)
    print(f"[OK] Integrity record saved -> {MANIFEST_PATH}")


def action_integrity(file_path: Path) -> None:
    if not MANIFEST_PATH.is_file():
        print("[ERROR] No manifest found yet. Protect a file first (option 1).")
        return

    manifest = integrity.load_manifest(MANIFEST_PATH)
    try:
        result = integrity.verify_file(manifest, file_path)
    except KeyError as exc:
        print(f"[ERROR] {exc}")
        return

    print(f"File      : {result.file_name}")
    print(f"Status    : {result.status}")
    print(f"Original  : {result.original_hash}")
    print(f"Current   : {result.current_hash}")


def action_vuln_demo() -> None:
    _ensure_dirs()
    print("[INFO] Encrypting a lab file with a deliberately weak passphrase...")
    encrypted_path, result = vulnerability_lab.run_weak_password_demo(LAB_ROOT)
    print(f"[INFO] Weak-passphrase lab file created -> {encrypted_path}")
    print(f"[INFO] Running bundled demo dictionary ({result.attempts if result.cracked else len(result.tried)} candidates)...")

    if result.cracked:
        print(f"[RESULT] Passphrase CRACKED after {result.attempts} attempts "
              f"in {result.elapsed_seconds:.4f}s -> '{result.found_password}'")
    else:
        print(f"[RESULT] Passphrase NOT found in demo dictionary "
              f"({result.attempts} attempts, {result.elapsed_seconds:.4f}s).")

    print("\n[LESSON] A short, common passphrase can be found almost instantly")
    print("with even a tiny wordlist. Use long, random, unique passphrases,")
    print("and a slow KDF (this project uses Scrypt) to raise the attacker's cost.")

    # Also demonstrate tamper detection on this same file.
    print("\n[INFO] Simulating tampering with the encrypted file...")
    tampered = vulnerability_lab.simulate_tamper(
        PROTECTED_DIR, MODIFIED_DIR, encrypted_path.name, LAB_ROOT
    )
    ok = decryption.try_decrypt(tampered, result.found_password or "123456")
    print(f"[RESULT] Decryption of tampered file succeeded: {ok} "
          "(should be False -- GCM detects tampering)")


def action_password_test(file_path: Path, custom_words: list[str] | None) -> None:
    if not file_path.is_file():
        print(f"[ERROR] File not found: {file_path}")
        return
    try:
        result = vulnerability_lab.dictionary_attack(file_path, LAB_ROOT, wordlist=custom_words)
    except vulnerability_lab.LabPathError as exc:
        print(f"[ERROR] {exc}")
        return

    if result.cracked:
        print(f"[RESULT] CRACKED after {result.attempts} attempts "
              f"in {result.elapsed_seconds:.4f}s -> '{result.found_password}'")
    else:
        print(f"[RESULT] NOT cracked with the demo dictionary "
              f"({result.attempts} attempts, {result.elapsed_seconds:.4f}s).")


def action_decrypt(file_path: Path, password: str) -> None:
    if not file_path.is_file():
        print(f"[ERROR] File not found: {file_path}")
        return

    dest = file_path.parent.parent / "original" / (file_path.stem + ".decrypted")
    try:
        decryption.decrypt_file(file_path, dest, password)
    except decryption.DecryptionError as exc:
        print(f"[FAILED] {exc}")
        return
    print(f"[OK] File decrypted -> {dest}")


def action_report(file_path: Path) -> None:
    if not file_path.is_file():
        print(f"[ERROR] File not found: {file_path}")
        return
    print(vulnerability_lab.legacy_hash_comparison(file_path))


# ----------------------------------------------------------------------
# Interactive menu
# ----------------------------------------------------------------------


def action_init_lab() -> None:
    """Populate lab/ with example files so every menu option works on a fresh clone.

    Creates a plaintext sample file, registers its SHA-256 in the manifest, and
    runs the weak-passphrase demo (which uses a demo passphrase that lives only
    in vulnerability_lab.py, never in a user secret). No user passphrase is
    stored or hardcoded here.
    """
    _ensure_dirs()

    sample = ORIGINAL_DIR / "sample.txt"
    if not sample.is_file():
        sample.write_text("Archivo de prueba del laboratorio.\n", encoding="utf-8")
        print(f"[OK] Archivo de ejemplo creado -> {sample}")

    manifest = (
        integrity.load_manifest(MANIFEST_PATH)
        if MANIFEST_PATH.is_file()
        else integrity.Manifest()
    )
    integrity.add_file_to_manifest(manifest, sample)
    integrity.save_manifest(manifest, MANIFEST_PATH)
    print(f"[OK] Manifiesto de integridad actualizado -> {MANIFEST_PATH}")

    encrypted_path, _ = vulnerability_lab.run_weak_password_demo(LAB_ROOT)
    print(f"[OK] Demo de contrasena debil creada -> {encrypted_path}")
    print("\nLab inicializado. Ahora puedes usar las opciones del menu.")
    print("Nota: lab/ esta excluido de git (.gitignore); estos archivos son locales.")


def _prompt_path(label: str, default: Path) -> Path:
    raw = input(f"{label} [{default}]: ").strip()
    return Path(raw) if raw else default


def interactive_menu() -> None:
    _ensure_dirs()
    print(BANNER)

    while True:
        print(
            "\n[1] Proteger archivo\n"
            "[2] Analizar integridad\n"
            "[3] Simular vulnerabilidad\n"
            "[4] Ejecutar prueba de contrasena\n"
            "[5] Descifrar archivo\n"
            "[6] Generar informe de seguridad\n"
            "[0] Salir"
        )
        choice = input("\n> Seleccione una opcion: ").strip()

        if choice == "1":
            path = _prompt_path("Ruta del archivo a proteger", ORIGINAL_DIR / "sample.txt")
            if not path.is_file():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Archivo de prueba del laboratorio.\n", encoding="utf-8")
                print(f"[INFO] Archivo de prueba creado en {path}")
            password = getpass.getpass("Contrasena (passphrase) para cifrar: ")
            action_protect(path, password)

        elif choice == "2":
            path = _prompt_path("Ruta del archivo original a verificar", ORIGINAL_DIR / "sample.txt")
            action_integrity(path)

        elif choice == "3":
            action_vuln_demo()

        elif choice == "4":
            path = _prompt_path(
                "Ruta del archivo .fslb (dentro de lab/) a probar",
                PROTECTED_DIR / "weak_demo.fslb",
            )
            action_password_test(path, None)

        elif choice == "5":
            path = _prompt_path("Ruta del archivo cifrado (.fslb)", PROTECTED_DIR / "sample.fslb")
            password = getpass.getpass("Contrasena (passphrase) para descifrar: ")
            action_decrypt(path, password)

        elif choice == "6":
            path = _prompt_path("Ruta del archivo para el informe", ORIGINAL_DIR / "sample.txt")
            action_report(path)

        elif choice == "0":
            print("Saliendo. Hasta luego.")
            break

        else:
            print("[ERROR] Opcion invalida.")


# ----------------------------------------------------------------------
# argparse (non-interactive) entry point
# ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="File Security Lab")
    sub = parser.add_subparsers(dest="command")

    p_protect = sub.add_parser("protect", help="Encrypt a file and record its integrity hash")
    p_protect.add_argument("--file", required=True, type=Path)
    p_protect.add_argument("--password", required=True)

    p_integrity = sub.add_parser("integrity", help="Verify a file against the manifest")
    p_integrity.add_argument("--file", required=True, type=Path)

    sub.add_parser("init-lab", help="Create example files in lab/ so all options work")
    sub.add_parser("vuln-demo", help="Run the weak-passphrase + tamper-detection demo")

    p_pwtest = sub.add_parser("password-test", help="Run the demo dictionary against a lab .fslb file")
    p_pwtest.add_argument("--file", required=True, type=Path)

    p_decrypt = sub.add_parser("decrypt", help="Decrypt a .fslb file")
    p_decrypt.add_argument("--file", required=True, type=Path)
    p_decrypt.add_argument("--password", required=True)

    p_report = sub.add_parser("report", help="Print MD5/SHA-1/SHA-256 comparison for a file")
    p_report.add_argument("--file", required=True, type=Path)

    return parser


def main(argv: list[str] | None = None) -> int:
    _ensure_dirs()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        interactive_menu()
        return 0

    if args.command == "protect":
        action_protect(args.file, args.password)
    elif args.command == "integrity":
        action_integrity(args.file)
    elif args.command == "init-lab":
        action_init_lab()
    elif args.command == "vuln-demo":
        action_vuln_demo()
    elif args.command == "password-test":
        action_password_test(args.file, None)
    elif args.command == "decrypt":
        action_decrypt(args.file, args.password)
    elif args.command == "report":
        action_report(args.file)

    return 0


if __name__ == "__main__":
    sys.exit(main())
