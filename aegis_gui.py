#!/usr/bin/env python3
"""
Aegis GUI — Шифровальщик сообщений и файлов
Зависимости: pip install argon2-cffi cryptography
"""

import os
import sys
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog
from pathlib import Path


def _resource(filename: str) -> str:
    """Путь к ресурсу — работает и из исходников, и из PyInstaller .exe."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, filename)


try:
    from aegis import encrypt, decrypt, encrypt_file, decrypt_file
except ImportError:
    print("Убедитесь, что aegis.py находится рядом с этим файлом.")
    sys.exit(1)

# ─── Цветовая схема ───────────────────────────────────────────────────────────

DARK    = "#0d1117"
PANEL   = "#161b22"
CARD    = "#21262d"
BORDER  = "#30363d"
ACCENT  = "#238636"
ACCENT2 = "#1f6feb"
RED     = "#da3633"
TEXT    = "#e6edf3"
MUTED   = "#8b949e"
GREEN   = "#3fb950"
YELLOW  = "#d29922"

FONT_MONO = ("Consolas", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_SM   = ("Segoe UI", 9)
FONT_BOLD = ("Segoe UI", 10, "bold")

# ─── Локализация ─────────────────────────────────────────────────────────────

STRINGS: dict[str, dict[str, str]] = {
    "ru": {
        # Окно и вкладки
        "window_title":        "Aegis — Шифровальщик",
        "tab_encrypt":         "  🔒  Шифрование  ",
        "tab_decrypt":         "  🔓  Дешифровка  ",
        # Секции паролей
        "enc_key_section":     "КЛЮЧ ШИФРОВАНИЯ",
        "dec_key_section":     "КЛЮЧ ДЕШИФРОВКИ",
        "lbl_password":        "Пароль:",
        "lbl_confirm":         "Повторить:",
        # Метки полей
        "lbl_plain_text":      "ИСХОДНЫЙ ТЕКСТ",
        "lbl_cipher_token":    "ЗАШИФРОВАННЫЙ ТОКЕН",
        "lbl_cipher_input":    "ЗАШИФРОВАННЫЙ ТОКЕН",
        "lbl_plain_result":    "РАСШИФРОВАННЫЙ ТЕКСТ",
        # Кнопки — шифрование
        "btn_encrypt":         "🔒  Зашифровать",
        "btn_copy":            "📋  Копировать",
        "btn_file":            "📂  Файл…",
        "btn_clear":           "Очистить",
        # Кнопки — дешифрование
        "btn_decrypt":         "🔓  Дешифровать",
        "btn_paste":           "📋  Вставить",
        # Статусбар
        "status_ready":        "Готово",
        "status_gen_keys":     "Генерация ключей…",
        "status_rest_keys":    "Восстановление ключей…",
        "status_enc_file":     "Шифрование файла…",
        "status_dec_file":     "Дешифровка файла…",
        # Ошибки
        "err_no_password":     "Введите пароль",
        "err_pw_mismatch":     "Пароли не совпадают",
        "err_no_text":         "Введите текст для шифрования",
        "err_no_token":        "Вставьте токен для дешифровки",
        "err_nothing_copy":    "Нечего копировать",
        "err_clipboard_empty": "Буфер обмена пуст",
        "err_pw_first":        "Сначала введите пароль",
        # Успех
        "ok_encrypted":        "Зашифровано  •  {} символов в токене",
        "ok_decrypted":        "Дешифровано  •  {} символов",
        "ok_token_copied":     "Токен скопирован в буфер обмена",
        "ok_pasted":           "Вставлено из буфера обмена",
        "ok_file_encrypted":   "Файл зашифрован → {}",
        "ok_file_decrypted":   "Файл дешифрован → {}",
        # Диалоги
        "dlg_open_enc":        "Выберите файл для шифрования",
        "dlg_save_enc":        "Сохранить зашифрованный файл",
        "dlg_open_dec":        "Выберите зашифрованный файл",
        "dlg_save_dec":        "Сохранить расшифрованный файл",
        "dlg_aegis_files":     "Aegis files",
        "dlg_all_files":       "All files",
    },
    "en": {
        # Window and tabs
        "window_title":        "Aegis — Encryptor",
        "tab_encrypt":         "  🔒  Encrypt  ",
        "tab_decrypt":         "  🔓  Decrypt  ",
        # Password sections
        "enc_key_section":     "ENCRYPTION KEY",
        "dec_key_section":     "DECRYPTION KEY",
        "lbl_password":        "Password:",
        "lbl_confirm":         "Confirm:",
        # Field labels
        "lbl_plain_text":      "PLAIN TEXT",
        "lbl_cipher_token":    "ENCRYPTED TOKEN",
        "lbl_cipher_input":    "ENCRYPTED TOKEN",
        "lbl_plain_result":    "DECRYPTED TEXT",
        # Buttons — encrypt
        "btn_encrypt":         "🔒  Encrypt",
        "btn_copy":            "📋  Copy",
        "btn_file":            "📂  File…",
        "btn_clear":           "Clear",
        # Buttons — decrypt
        "btn_decrypt":         "🔓  Decrypt",
        "btn_paste":           "📋  Paste",
        # Status bar
        "status_ready":        "Ready",
        "status_gen_keys":     "Generating keys…",
        "status_rest_keys":    "Restoring keys…",
        "status_enc_file":     "Encrypting file…",
        "status_dec_file":     "Decrypting file…",
        # Errors
        "err_no_password":     "Enter password",
        "err_pw_mismatch":     "Passwords do not match",
        "err_no_text":         "Enter text to encrypt",
        "err_no_token":        "Paste token to decrypt",
        "err_nothing_copy":    "Nothing to copy",
        "err_clipboard_empty": "Clipboard is empty",
        "err_pw_first":        "Enter password first",
        # Success
        "ok_encrypted":        "Encrypted  •  {} chars in token",
        "ok_decrypted":        "Decrypted  •  {} chars",
        "ok_token_copied":     "Token copied to clipboard",
        "ok_pasted":           "Pasted from clipboard",
        "ok_file_encrypted":   "File encrypted → {}",
        "ok_file_decrypted":   "File decrypted → {}",
        # Dialogs
        "dlg_open_enc":        "Select file to encrypt",
        "dlg_save_enc":        "Save encrypted file",
        "dlg_open_dec":        "Select encrypted file",
        "dlg_save_dec":        "Save decrypted file",
        "dlg_aegis_files":     "Aegis files",
        "dlg_all_files":       "All files",
    },
}


class I18n:
    """
    Хранит текущий язык и StringVar для каждого ключа.
    При смене языка обновляет все зарегистрированные переменные разом.
    """
    def __init__(self, lang: str = "ru"):
        self._lang = lang
        self._vars: dict[str, tk.StringVar] = {}

    # ── публичный интерфейс ──────────────────────────────────────────────────

    def var(self, key: str) -> tk.StringVar:
        """Возвращает StringVar, привязанный к ключу. Создаёт при первом вызове."""
        if key not in self._vars:
            self._vars[key] = tk.StringVar(value=STRINGS[self._lang][key])
        return self._vars[key]

    def t(self, key: str) -> str:
        """Возвращает текущий перевод строки (для диалогов и f-строк)."""
        return STRINGS[self._lang][key]

    def switch(self, lang: str) -> None:
        """Переключает язык и обновляет все StringVar."""
        self._lang = lang
        for key, var in self._vars.items():
            var.set(STRINGS[lang][key])

    @property
    def lang(self) -> str:
        return self._lang


# ─── Вспомогательные виджеты ─────────────────────────────────────────────────

class StatusBar(tk.Frame):
    def __init__(self, master, i18n: I18n, **kw):
        super().__init__(master, bg=PANEL, height=28, **kw)
        self._i18n = i18n
        self._var = tk.StringVar()
        # При смене языка и статусе «Готово» — обновляем текст
        i18n.var("status_ready").trace_add("write",
            lambda *_: self._on_ready_changed())
        self._var.set(i18n.t("status_ready"))
        self._is_ready = True

        self._lbl = tk.Label(self, textvariable=self._var,
                             font=FONT_SM, bg=PANEL, fg=MUTED, anchor="w", padx=12)
        self._lbl.pack(side="left", fill="x", expand=True)

    def _on_ready_changed(self):
        if self._is_ready:
            self._var.set(self._i18n.t("status_ready"))
            self._lbl.config(fg=MUTED)

    def set(self, msg: str, color: str = MUTED):
        self._is_ready = False
        self._var.set(msg)
        self._lbl.config(fg=color)

    def ok(self, msg):
        self._is_ready = False
        self.set("✔  " + msg, GREEN)

    def err(self, msg):
        self._is_ready = False
        self.set("✘  " + msg, RED)

    def info(self, msg):
        self._is_ready = False
        self.set("⏳  " + msg, YELLOW)

    def ready(self):
        self._is_ready = True
        self.set(self._i18n.t("status_ready"))


class PasswordEntry(tk.Frame):
    """Поле пароля с кнопкой показать/скрыть."""
    def __init__(self, master, label_key: str, i18n: I18n, **kw):
        super().__init__(master, bg=CARD, **kw)
        tk.Label(self, textvariable=i18n.var(label_key),
                 font=FONT_UI, bg=CARD, fg=MUTED,
                 width=14, anchor="w").pack(side="left", padx=(10, 4))
        self._var = tk.StringVar()
        self._entry = tk.Entry(self, textvariable=self._var, show="●",
                               font=FONT_MONO, bg=DARK, fg=TEXT,
                               insertbackground=TEXT, relief="flat", bd=0,
                               highlightthickness=1,
                               highlightbackground=BORDER, highlightcolor=ACCENT2)
        self._entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 2))
        self._eye = tk.Button(self, text="👁", font=("Segoe UI", 9),
                              bg=CARD, fg=MUTED, activebackground=BORDER,
                              activeforeground=TEXT, relief="flat", cursor="hand2",
                              takefocus=False, command=self._toggle)
        self._eye.pack(side="left", padx=(0, 8))
        self._shown = False

    def _toggle(self):
        self._shown = not self._shown
        self._entry.config(show="" if self._shown else "●")

    def get(self) -> str:
        return self._var.get()

    def clear(self):
        self._var.set("")


class ScrolledText(tk.Frame):
    """Text с вертикальным скроллбаром."""
    def __init__(self, master, readonly: bool = False, **kw):
        super().__init__(master, bg=DARK, **kw)
        sb = tk.Scrollbar(self, bg=PANEL, troughcolor=DARK,
                          activebackground=BORDER, relief="flat", bd=0, width=10)
        state = "disabled" if readonly else "normal"
        self.text = tk.Text(self, font=FONT_MONO, bg=DARK, fg=TEXT,
                            insertbackground=TEXT, relief="flat", bd=0,
                            wrap="word", state=state,
                            selectbackground=ACCENT2, selectforeground=TEXT,
                            yscrollcommand=sb.set, highlightthickness=1,
                            highlightbackground=BORDER, highlightcolor=ACCENT2)
        sb.config(command=self.text.yview)
        self.text.pack(side="left", fill="both", expand=True, padx=1, pady=1)
        sb.pack(side="right", fill="y", pady=1)

    def get_all(self) -> str:
        return self.text.get("1.0", "end-1c")

    def set_readonly(self, content: str):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", content)
        self.text.config(state="disabled")

    def clear(self):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")


def _btn(parent, textvar: tk.StringVar, cmd, color=ACCENT):
    return tk.Button(parent, textvariable=textvar, command=cmd,
                     font=FONT_BOLD, bg=color, fg=TEXT,
                     activebackground=BORDER, activeforeground=TEXT,
                     relief="flat", cursor="hand2", padx=14, pady=6)


def _separator(parent):
    return tk.Frame(parent, bg=BORDER, height=1)


# ─── Вкладка «Шифрование» ────────────────────────────────────────────────────

class EncryptTab(tk.Frame):
    def __init__(self, master, status: StatusBar, i18n: I18n, **kw):
        super().__init__(master, bg=DARK, **kw)
        self._status = status
        self._i18n = i18n
        self._build()

    def _build(self):
        i = self._i18n

        # ── Пароль ──
        pw_card = tk.Frame(self, bg=CARD)
        pw_card.pack(fill="x", padx=16, pady=(16, 6))
        tk.Label(pw_card, textvariable=i.var("enc_key_section"),
                 font=FONT_SM, bg=CARD, fg=MUTED).pack(anchor="w", padx=12, pady=(8, 2))
        self._pw1 = PasswordEntry(pw_card, "lbl_password", i)
        self._pw1.pack(fill="x", pady=(0, 4))
        self._pw2 = PasswordEntry(pw_card, "lbl_confirm", i)
        self._pw2.pack(fill="x", pady=(0, 8))

        # ── Кнопки (до mid) ──
        btn_row = tk.Frame(self, bg=DARK)
        btn_row.pack(fill="x", padx=16, pady=12, side="bottom")
        _btn(btn_row, i.var("btn_encrypt"), self._do_encrypt, ACCENT).pack(side="left", padx=(0, 8))
        _btn(btn_row, i.var("btn_copy"),    self._copy,       ACCENT2).pack(side="left", padx=(0, 8))
        _btn(btn_row, i.var("btn_file"),    self._file_encrypt, CARD).pack(side="left")
        _btn(btn_row, i.var("btn_clear"),   self._clear,      CARD).pack(side="right")

        # ── Текстовые поля ──
        mid = tk.Frame(self, bg=DARK)
        mid.pack(fill="both", expand=True, padx=16, pady=6)

        tk.Label(mid, textvariable=i.var("lbl_plain_text"),
                 font=FONT_SM, bg=DARK, fg=MUTED).pack(anchor="w")
        self._input = ScrolledText(mid)
        self._input.pack(fill="both", expand=True, pady=(2, 8))

        tk.Label(mid, textvariable=i.var("lbl_cipher_token"),
                 font=FONT_SM, bg=DARK, fg=MUTED).pack(anchor="w")
        self._output = ScrolledText(mid, readonly=True)
        self._output.pack(fill="both", expand=True, pady=(2, 0))

    def _do_encrypt(self):
        pw1  = self._pw1.get()
        pw2  = self._pw2.get()
        text = self._input.get_all().strip()
        i    = self._i18n
        if not pw1:
            self._status.err(i.t("err_no_password")); return
        if pw1 != pw2:
            self._status.err(i.t("err_pw_mismatch")); return
        if not text:
            self._status.err(i.t("err_no_text")); return
        self._status.info(i.t("status_gen_keys"))
        self.after(10, lambda: self._run_encrypt(text, pw1))

    def _run_encrypt(self, text, pw):
        q = queue.Queue()

        def work():
            try:
                q.put(("ok", encrypt(text, pw)))
            except Exception as e:
                q.put(("err", str(e)))

        def poll():
            try:
                kind, val = q.get_nowait()
                if kind == "ok":
                    self._output.set_readonly(val)
                    self._status.ok(self._i18n.t("ok_encrypted").format(len(val)))
                else:
                    self._status.err(val)
            except queue.Empty:
                self.after(50, poll)

        threading.Thread(target=work, daemon=True).start()
        self.after(50, poll)

    def _copy(self):
        token = self._output.get_all().strip()
        if not token:
            self._status.err(self._i18n.t("err_nothing_copy")); return
        self.clipboard_clear()
        self.clipboard_append(token)
        self._status.ok(self._i18n.t("ok_token_copied"))

    def _file_encrypt(self):
        i   = self._i18n
        src = filedialog.askopenfilename(title=i.t("dlg_open_enc"))
        if not src:
            return
        pw1 = self._pw1.get()
        pw2 = self._pw2.get()
        if not pw1:
            self._status.err(i.t("err_pw_first")); return
        if pw1 != pw2:
            self._status.err(i.t("err_pw_mismatch")); return

        dst = filedialog.asksaveasfilename(
            title=i.t("dlg_save_enc"),
            initialfile=Path(src).stem + ".qc",
            defaultextension=".qc")
        if not dst:
            return

        self._status.info(i.t("status_enc_file"))
        q = queue.Queue()

        def work():
            try:
                encrypt_file(src, dst, pw1)
                q.put(("ok", Path(dst).name))
            except Exception as e:
                q.put(("err", str(e)))

        def poll():
            try:
                kind, val = q.get_nowait()
                if kind == "ok":
                    self._status.ok(self._i18n.t("ok_file_encrypted").format(val))
                else:
                    self._status.err(val)
            except queue.Empty:
                self.after(50, poll)

        threading.Thread(target=work, daemon=True).start()
        self.after(50, poll)

    def _clear(self):
        self._input.clear()
        self._output.clear()
        self._pw1.clear()
        self._pw2.clear()
        self._status.ready()


# ─── Вкладка «Дешифрование» ──────────────────────────────────────────────────

class DecryptTab(tk.Frame):
    def __init__(self, master, status: StatusBar, i18n: I18n, **kw):
        super().__init__(master, bg=DARK, **kw)
        self._status = status
        self._i18n = i18n
        self._build()

    def _build(self):
        i = self._i18n

        # ── Пароль ──
        pw_card = tk.Frame(self, bg=CARD)
        pw_card.pack(fill="x", padx=16, pady=(16, 6))
        tk.Label(pw_card, textvariable=i.var("dec_key_section"),
                 font=FONT_SM, bg=CARD, fg=MUTED).pack(anchor="w", padx=12, pady=(8, 2))
        self._pw = PasswordEntry(pw_card, "lbl_password", i)
        self._pw.pack(fill="x", pady=(0, 8))

        # ── Кнопки (до mid) ──
        btn_row = tk.Frame(self, bg=DARK)
        btn_row.pack(fill="x", padx=16, pady=12, side="bottom")
        _btn(btn_row, i.var("btn_decrypt"), self._do_decrypt, ACCENT).pack(side="left", padx=(0, 8))
        _btn(btn_row, i.var("btn_paste"),   self._paste,      ACCENT2).pack(side="left", padx=(0, 8))
        _btn(btn_row, i.var("btn_file"),    self._file_decrypt, CARD).pack(side="left")
        _btn(btn_row, i.var("btn_clear"),   self._clear,      CARD).pack(side="right")

        # ── Текстовые поля ──
        mid = tk.Frame(self, bg=DARK)
        mid.pack(fill="both", expand=True, padx=16, pady=6)

        tk.Label(mid, textvariable=i.var("lbl_cipher_input"),
                 font=FONT_SM, bg=DARK, fg=MUTED).pack(anchor="w")
        self._input = ScrolledText(mid)
        self._input.pack(fill="both", expand=True, pady=(2, 8))

        tk.Label(mid, textvariable=i.var("lbl_plain_result"),
                 font=FONT_SM, bg=DARK, fg=MUTED).pack(anchor="w")
        self._output = ScrolledText(mid, readonly=True)
        self._output.pack(fill="both", expand=True, pady=(2, 0))

    def _do_decrypt(self):
        pw    = self._pw.get()
        token = self._input.get_all().replace("\n", "").strip()
        i     = self._i18n
        if not pw:
            self._status.err(i.t("err_no_password")); return
        if not token:
            self._status.err(i.t("err_no_token")); return
        self._status.info(i.t("status_rest_keys"))
        self.after(10, lambda: self._run_decrypt(token, pw))

    def _run_decrypt(self, token, pw):
        q = queue.Queue()

        def work():
            try:
                q.put(("ok", decrypt(token, pw)))
            except Exception as e:
                q.put(("err", str(e)))

        def poll():
            try:
                kind, val = q.get_nowait()
                if kind == "ok":
                    self._output.set_readonly(val)
                    self._status.ok(self._i18n.t("ok_decrypted").format(len(val)))
                else:
                    self._output.set_readonly("")
                    self._status.err(val)
            except queue.Empty:
                self.after(50, poll)

        threading.Thread(target=work, daemon=True).start()
        self.after(50, poll)

    def _paste(self):
        try:
            content = self.clipboard_get()
            self._input.clear()
            self._input.text.config(state="normal")
            self._input.text.insert("1.0", content)
            self._status.ok(self._i18n.t("ok_pasted"))
        except tk.TclError:
            self._status.err(self._i18n.t("err_clipboard_empty"))

    def _file_decrypt(self):
        i   = self._i18n
        src = filedialog.askopenfilename(
            title=i.t("dlg_open_dec"),
            filetypes=[(i.t("dlg_aegis_files"), "*.qc"),
                       (i.t("dlg_all_files"),   "*.*")])
        if not src:
            return
        pw = self._pw.get()
        if not pw:
            self._status.err(i.t("err_pw_first")); return

        dst = filedialog.asksaveasfilename(
            title=i.t("dlg_save_dec"),
            initialfile=Path(src).stem)
        if not dst:
            return

        self._status.info(i.t("status_dec_file"))
        q = queue.Queue()

        def work():
            try:
                decrypt_file(src, dst, pw)
                q.put(("ok", Path(dst).name))
            except Exception as e:
                q.put(("err", str(e)))

        def poll():
            try:
                kind, val = q.get_nowait()
                if kind == "ok":
                    self._status.ok(self._i18n.t("ok_file_decrypted").format(val))
                else:
                    self._status.err(val)
            except queue.Empty:
                self.after(50, poll)

        threading.Thread(target=work, daemon=True).start()
        self.after(50, poll)

    def _clear(self):
        self._input.clear()
        self._output.clear()
        self._pw.clear()
        self._status.ready()


# ─── Главное окно ────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self._i18n = I18n("ru")
        self.title(self._i18n.t("window_title"))
        self._i18n.var("window_title").trace_add("write",
            lambda *_: self.title(self._i18n.t("window_title")))

        self.geometry("860x820")
        self.minsize(700, 700)
        self.configure(bg=DARK)

        try:
            self.iconbitmap(default=_resource("aega2.ico"))
        except Exception:
            pass

        self._build()

    def _build(self):
        i = self._i18n

        # ── Заголовок ──
        header = tk.Frame(self, bg=PANEL, height=52)
        header.pack(fill="x")
        header.pack_propagate(False)

        title_frame = tk.Frame(header, bg=PANEL)
        title_frame.pack(side="left", padx=18, pady=8)
        tk.Label(title_frame, text="🔐 Aegis",
                 font=("Segoe UI", 14, "bold"), bg=PANEL, fg=TEXT).pack(side="left")
        tk.Label(title_frame, text="  v1.0.1",
                 font=FONT_SM, bg=PANEL, fg=MUTED).pack(side="left", pady=2)

        # ── Переключатель языка ──
        lang_frame = tk.Frame(header, bg=PANEL)
        lang_frame.pack(side="right", padx=12, pady=12)

        self._btn_ru = tk.Button(
            lang_frame, text="RU", font=FONT_SM,
            bg=ACCENT, fg=TEXT, activebackground=BORDER, activeforeground=TEXT,
            relief="flat", cursor="hand2", padx=8, pady=2,
            command=lambda: self._set_lang("ru"))
        self._btn_ru.pack(side="left", padx=(0, 2))

        self._btn_en = tk.Button(
            lang_frame, text="EN", font=FONT_SM,
            bg=CARD, fg=MUTED, activebackground=BORDER, activeforeground=TEXT,
            relief="flat", cursor="hand2", padx=8, pady=2,
            command=lambda: self._set_lang("en"))
        self._btn_en.pack(side="left")

        badge = tk.Frame(header, bg=CARD, padx=8, pady=3)
        badge.pack(side="right", padx=8, pady=12)
        tk.Label(badge, text="AES-256 · ChaCha20 · Argon2id",
                 font=FONT_SM, bg=CARD, fg=MUTED).pack()

        _separator(self).pack(fill="x")

        # ── Стиль вкладок ──
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TNotebook",
                        background=DARK, borderwidth=0, tabmargins=0)
        style.configure("TNotebook.Tab",
                        background=PANEL, foreground=MUTED,
                        font=FONT_BOLD, padding=(18, 8),
                        borderwidth=0, focuscolor=DARK)
        style.map("TNotebook.Tab",
                  background=[("selected", DARK)],
                  foreground=[("selected", TEXT)])

        self._nb = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True)

        # ── Статус-бар ──
        self._status = StatusBar(self, i)
        self._status.pack(fill="x", side="bottom")
        _separator(self).pack(fill="x", side="bottom")

        # ── Вкладки ──
        self._enc_tab = EncryptTab(self._nb, self._status, i)
        self._dec_tab = DecryptTab(self._nb, self._status, i)
        self._nb.add(self._enc_tab, text=i.t("tab_encrypt"))
        self._nb.add(self._dec_tab, text=i.t("tab_decrypt"))

    def _set_lang(self, lang: str):
        if lang == self._i18n.lang:
            return
        self._i18n.switch(lang)
        # Обновить заголовки вкладок (notebook не поддерживает StringVar)
        self._nb.tab(0, text=self._i18n.t("tab_encrypt"))
        self._nb.tab(1, text=self._i18n.t("tab_decrypt"))
        # Подсветить активную кнопку
        if lang == "ru":
            self._btn_ru.config(bg=ACCENT, fg=TEXT)
            self._btn_en.config(bg=CARD,   fg=MUTED)
        else:
            self._btn_en.config(bg=ACCENT, fg=TEXT)
            self._btn_ru.config(bg=CARD,   fg=MUTED)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
