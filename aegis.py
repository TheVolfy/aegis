#!/usr/bin/env python3
"""
Aegis — Шифровальщик сообщений и файлов
----------------------------------------
Алгоритмы:
  KDF    : Argon2id (RFC 9106)
  Слой 1 : AES-256-GCM
  Слой 2 : ChaCha20-Poly1305

Без пароля — дешифровка невозможна даже при наличии исходного кода.
Работает полностью оффлайн.

Зависимости: pip install argon2-cffi cryptography
"""

import os
import sys
import struct
import base64
import secrets
import getpass
import argparse
import textwrap

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("[!] Установите зависимости: pip install argon2-cffi cryptography")
    sys.exit(1)

# ─── Константы ────────────────────────────────────────────────────────────────

FORMAT_VERSION   = 0x01

# Argon2id параметры (OWASP/RFC 9106 «high security»)
ARGON2_TIME_COST   = 4          # итерации
ARGON2_MEM_COST    = 131_072    # 128 МБ памяти
ARGON2_PARALLELISM = 4          # потоки
ARGON2_HASH_LEN    = 64         # 512 бит → два ключа по 256 бит

SALT_LEN        = 32            # 256-битная соль
AES_NONCE_LEN   = 12            # 96-битный nonce для GCM
CHA_NONCE_LEN   = 12            # 96-битный nonce для ChaCha20

# Структура бинарного пакета:
# [version:1][salt:32][aes_nonce:12][cha_nonce:12][ciphertext:N]
HEADER_LEN = 1 + SALT_LEN + AES_NONCE_LEN + CHA_NONCE_LEN


# ─── Криптоядро ───────────────────────────────────────────────────────────────

def _derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """
    Argon2id: из пароля и соли выводит 64 байта ключевого материала.
    Первые 32 → ключ AES-256-GCM, следующие 32 → ключ ChaCha20-Poly1305.
    """
    raw = hash_secret_raw(
        secret      = password.encode("utf-8"),
        salt        = salt,
        time_cost   = ARGON2_TIME_COST,
        memory_cost = ARGON2_MEM_COST,
        parallelism = ARGON2_PARALLELISM,
        hash_len    = ARGON2_HASH_LEN,
        type        = Argon2Type.ID,
    )
    return raw[:32], raw[32:]


def encrypt(plaintext: str, password: str) -> str:
    """
    Шифрует сообщение двумя независимыми AEAD-алгоритмами поверх друг друга.
    Возвращает Base64url-строку (безопасна для копипасты и email).
    """
    salt      = secrets.token_bytes(SALT_LEN)
    aes_key, cha_key = _derive_keys(password, salt)

    # Слой 1 — AES-256-GCM
    aes_nonce = secrets.token_bytes(AES_NONCE_LEN)
    layer1    = AESGCM(aes_key).encrypt(aes_nonce, plaintext.encode("utf-8"), None)

    # Слой 2 — ChaCha20-Poly1305 (шифрует вывод слоя 1 целиком, включая тег)
    cha_nonce = secrets.token_bytes(CHA_NONCE_LEN)
    layer2    = ChaCha20Poly1305(cha_key).encrypt(cha_nonce, layer1, None)

    # Сборка пакета
    packet = struct.pack("B", FORMAT_VERSION) + salt + aes_nonce + cha_nonce + layer2
    return base64.urlsafe_b64encode(packet).decode("ascii")


def decrypt(token: str, password: str) -> str:
    """
    Дешифрует токен. При неверном пароле или повреждённых данных
    бросает ValueError (намеренно без деталей — не раскрываем причину).
    """
    try:
        packet = base64.urlsafe_b64decode(token.strip())
    except Exception:
        raise ValueError("Некорректный формат: не является Base64url.")

    if len(packet) < HEADER_LEN + 1:
        raise ValueError("Пакет слишком короткий.")

    version = packet[0]
    if version != FORMAT_VERSION:
        raise ValueError(f"Неизвестная версия формата: {version:#04x}")

    off        = 1
    salt       = packet[off : off + SALT_LEN];       off += SALT_LEN
    aes_nonce  = packet[off : off + AES_NONCE_LEN];  off += AES_NONCE_LEN
    cha_nonce  = packet[off : off + CHA_NONCE_LEN];  off += CHA_NONCE_LEN
    ciphertext = packet[off:]

    aes_key, cha_key = _derive_keys(password, salt)

    # Слой 2 → Слой 1
    try:
        layer1 = ChaCha20Poly1305(cha_key).decrypt(cha_nonce, ciphertext, None)
    except (InvalidTag, Exception):
        raise ValueError("Дешифровка не удалась — неверный пароль или повреждённые данные.")

    # Слой 1 → открытый текст
    try:
        plaintext_bytes = AESGCM(aes_key).decrypt(aes_nonce, layer1, None)
    except (InvalidTag, Exception):
        raise ValueError("Дешифровка не удалась — неверный пароль или повреждённые данные.")

    return plaintext_bytes.decode("utf-8")


# ─── Работа с файлами ─────────────────────────────────────────────────────────

def encrypt_file(src: str, dst: str, password: str) -> None:
    with open(src, "rb") as f:
        data = f.read()
    token = _encrypt_bytes(data, password)
    with open(dst, "w", encoding="ascii") as f:
        f.write("\n".join(textwrap.wrap(token, 76)))
        f.write("\n")


def decrypt_file(src: str, dst: str, password: str) -> None:
    with open(src, "r", encoding="ascii") as f:
        token = f.read().replace("\n", "").strip()
    data = _decrypt_bytes(token, password)
    with open(dst, "wb") as f:
        f.write(data)


def _encrypt_bytes(data: bytes, password: str) -> str:
    salt      = secrets.token_bytes(SALT_LEN)
    aes_key, cha_key = _derive_keys(password, salt)
    aes_nonce = secrets.token_bytes(AES_NONCE_LEN)
    layer1    = AESGCM(aes_key).encrypt(aes_nonce, data, None)
    cha_nonce = secrets.token_bytes(CHA_NONCE_LEN)
    layer2    = ChaCha20Poly1305(cha_key).encrypt(cha_nonce, layer1, None)
    packet    = struct.pack("B", FORMAT_VERSION) + salt + aes_nonce + cha_nonce + layer2
    return base64.urlsafe_b64encode(packet).decode("ascii")


def _decrypt_bytes(token: str, password: str) -> bytes:
    packet    = base64.urlsafe_b64decode(token)
    version   = packet[0]
    if version != FORMAT_VERSION:
        raise ValueError(f"Неизвестная версия: {version}")
    off       = 1
    salt      = packet[off:off+SALT_LEN];      off += SALT_LEN
    aes_nonce = packet[off:off+AES_NONCE_LEN]; off += AES_NONCE_LEN
    cha_nonce = packet[off:off+CHA_NONCE_LEN]; off += CHA_NONCE_LEN
    ct        = packet[off:]
    aes_key, cha_key = _derive_keys(password, salt)
    try:
        layer1 = ChaCha20Poly1305(cha_key).decrypt(cha_nonce, ct, None)
        return AESGCM(aes_key).decrypt(aes_nonce, layer1, None)
    except Exception:
        raise ValueError("Дешифровка не удалась — неверный пароль или повреждённые данные.")


# ─── CLI ──────────────────────────────────────────────────────────────────────

BANNER = r"""
    _       _
   / \  ___| |_ ___ _ __ __
  / _ \/ _ \ __/ _ \ '_ \/ /
 / ___ \  __/ ||  __/ | |  /
/_/   \_\___|\__\___|_| |_/

  Aegis  •  Шифровальщик сообщений и файлов  •  v1.0
"""


def _get_password(prompt: str, confirm: bool = False) -> str:
    pw = getpass.getpass(prompt)
    if not pw:
        print("[!] Пароль не может быть пустым.")
        sys.exit(1)
    if confirm:
        pw2 = getpass.getpass("  Повторите пароль: ")
        if pw != pw2:
            print("[!] Пароли не совпадают.")
            sys.exit(1)
    return pw


def _multiline_input(prompt: str) -> str:
    """Ввод многострочного текста (Ctrl+D для завершения)."""
    print(prompt)
    lines = []
    try:
        while True:
            line = input()
            lines.append(line)
    except EOFError:
        pass
    return "\n".join(lines)


def cmd_encrypt(args):
    if args.file:
        pw = _get_password("  Пароль (шифрование): ", confirm=True)
        out = args.output or (args.file + ".qc")
        print("  [*] Генерация ключей (это займёт несколько секунд)...")
        encrypt_file(args.file, out, pw)
        print(f"  [+] Зашифровано → {out}")
        return

    if args.message:
        text = args.message
    else:
        text = _multiline_input("  Введите сообщение (Ctrl+D для завершения):")

    pw = _get_password("  Пароль (шифрование): ", confirm=True)
    print("  [*] Генерация ключей (это займёт несколько секунд)...")
    token = encrypt(text, pw)
    print("\n" + "─" * 60)
    print("  ЗАШИФРОВАННОЕ СООБЩЕНИЕ:")
    print("─" * 60)
    for chunk in textwrap.wrap(token, 72):
        print("  " + chunk)
    print("─" * 60 + "\n")

    if args.output:
        with open(args.output, "w", encoding="ascii") as f:
            f.write(token + "\n")
        print(f"  [+] Сохранено в {args.output}")


def cmd_decrypt(args):
    if args.file:
        pw = _get_password("  Пароль (дешифровка): ")
        out = args.output or (
            args.file[:-3] if args.file.endswith(".qc") else args.file + ".dec"
        )
        print("  [*] Восстановление ключей...")
        try:
            decrypt_file(args.file, out, pw)
            print(f"  [+] Расшифровано → {out}")
        except ValueError as e:
            print(f"  [!] {e}")
            sys.exit(1)
        return

    if args.token:
        token = args.token
    elif args.input:
        with open(args.input, "r", encoding="ascii") as f:
            token = f.read().replace("\n", "").strip()
    else:
        print("  Вставьте зашифрованное сообщение (Ctrl+D для завершения):")
        token = _multiline_input("").replace("\n", "").strip()

    pw = _get_password("  Пароль (дешифровка): ")
    print("  [*] Восстановление ключей...")
    try:
        text = decrypt(token, pw)
        print("\n" + "─" * 60)
        print("  РАСШИФРОВАННОЕ СООБЩЕНИЕ:")
        print("─" * 60)
        print(text)
        print("─" * 60 + "\n")
    except ValueError as e:
        print(f"\n  [!] {e}")
        sys.exit(1)


def cmd_info(_args):
    print(f"""
  Алгоритм KDF : Argon2id
    Время       : {ARGON2_TIME_COST} итерации
    Память      : {ARGON2_MEM_COST // 1024} МБ
    Параллелизм : {ARGON2_PARALLELISM} потока
    Длина ключа : {ARGON2_HASH_LEN} байт → 2 × 256-бит ключа

  Шифрование   : AES-256-GCM       (слой 1)
               : ChaCha20-Poly1305  (слой 2, поверх слоя 1)
  Аутентификация: встроенная AEAD   (каждый слой имеет MAC-тег)
  Соль         : 256 бит, случайная для каждого сообщения
""")


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis — шифровальщик сообщений и файлов",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", metavar="КОМАНДА")

    # encrypt
    p_enc = sub.add_parser("encrypt", aliases=["e", "enc"],
                            help="Зашифровать сообщение или файл")
    p_enc.add_argument("-m", "--message", metavar="TEXT",
                       help="Текст для шифрования (иначе — интерактивный ввод)")
    p_enc.add_argument("-f", "--file",    metavar="FILE",
                       help="Файл для шифрования")
    p_enc.add_argument("-o", "--output",  metavar="FILE",
                       help="Файл для сохранения результата")

    # decrypt
    p_dec = sub.add_parser("decrypt", aliases=["d", "dec"],
                            help="Дешифровать сообщение или файл")
    p_dec.add_argument("-t", "--token",   metavar="TOKEN",
                       help="Base64url-токен для дешифровки")
    p_dec.add_argument("-f", "--file",    metavar="FILE",
                       help="Зашифрованный файл (.qc)")
    p_dec.add_argument("-i", "--input",   metavar="FILE",
                       help="Файл с токеном")
    p_dec.add_argument("-o", "--output",  metavar="FILE",
                       help="Куда сохранить расшифрованный файл")

    # info
    sub.add_parser("info", help="Показать параметры шифрования")

    if len(sys.argv) == 1:
        parser.print_help()
        return

    args = parser.parse_args()

    dispatch = {
        "encrypt": cmd_encrypt, "e": cmd_encrypt, "enc": cmd_encrypt,
        "decrypt": cmd_decrypt, "d": cmd_decrypt, "dec": cmd_decrypt,
        "info":    cmd_info,
    }

    handler = dispatch.get(args.cmd)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
