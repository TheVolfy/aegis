#!/usr/bin/env python3
"""
Aegis GUI — Шифровальщик сообщений и файлов
Зависимости: pip install argon2-cffi cryptography
"""

import sys
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

try:
    from aegis import encrypt, decrypt, encrypt_file, decrypt_file
except ImportError:
    print("Убедитесь, что aegis.py находится рядом с этим файлом.")
    sys.exit(1)

# ─── Цветовая схема ───────────────────────────────────────────────────────────

DARK   = "#0d1117"
PANEL  = "#161b22"
CARD   = "#21262d"
BORDER = "#30363d"
ACCENT = "#238636"
ACCENT2= "#1f6feb"
RED    = "#da3633"
TEXT   = "#e6edf3"
MUTED  = "#8b949e"
GREEN  = "#3fb950"
YELLOW = "#d29922"

FONT_MONO  = ("Consolas", 10)
FONT_UI    = ("Segoe UI", 10)
FONT_UI_SM = ("Segoe UI", 9)
FONT_TITLE = ("Segoe UI", 13, "bold")
FONT_HEAD  = ("Segoe UI", 10, "bold")


# ─── Вспомогательные виджеты ─────────────────────────────────────────────────

class StatusBar(tk.Frame):
    def __init__(self, master, **kw):
        super().__init__(master, bg=PANEL, height=28, **kw)
        self._var = tk.StringVar(value="Готово")
        self._lbl = tk.Label(self, textvariable=self._var,
                             font=FONT_UI_SM, bg=PANEL, fg=MUTED, anchor="w",
                             padx=12)
        self._lbl.pack(side="left", fill="x", expand=True)

    def set(self, msg: str, color: str = MUTED):
        self._var.set(msg)
        self._lbl.config(fg=color)

    def ok(self, msg):   self.set("✔  " + msg, GREEN)
    def err(self, msg):  self.set("✘  " + msg, RED)
    def info(self, msg): self.set("⏳  " + msg, YELLOW)


class PasswordEntry(tk.Frame):
    """Поле пароля с кнопкой показать/скрыть."""
    def __init__(self, master, label="Пароль:", **kw):
        super().__init__(master, bg=CARD, **kw)
        tk.Label(self, text=label, font=FONT_UI, bg=CARD, fg=MUTED,
                 width=14, anchor="w").pack(side="left", padx=(10, 4))
        self._var = tk.StringVar()
        self._entry = tk.Entry(self, textvariable=self._var, show="●",
                               font=FONT_MONO, bg=DARK, fg=TEXT, insertbackground=TEXT,
                               relief="flat", bd=0, highlightthickness=1,
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
    def __init__(self, master, readonly=False, **kw):
        super().__init__(master, bg=DARK, **kw)
        sb = tk.Scrollbar(self, bg=PANEL, troughcolor=DARK,
                          activebackground=BORDER, relief="flat", bd=0, width=10)
        state = "disabled" if readonly else "normal"
        self.text = tk.Text(self, font=FONT_MONO, bg=DARK, fg=TEXT,
                            insertbackground=TEXT, relief="flat", bd=0,
                            wrap="word", state=state,
                            selectbackground=ACCENT2, selectforeground=TEXT,
                            yscrollcommand=sb.set,
                            highlightthickness=1,
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


def _btn(parent, text, cmd, color=ACCENT, width=None):
    return tk.Button(parent, text=text, command=cmd,
                     font=FONT_HEAD, bg=color, fg=TEXT,
                     activebackground=BORDER, activeforeground=TEXT,
                     relief="flat", cursor="hand2", padx=14, pady=6,
                     width=width or 0)


def _separator(parent):
    return tk.Frame(parent, bg=BORDER, height=1)


# ─── Вкладка «Шифрование» ────────────────────────────────────────────────────

class EncryptTab(tk.Frame):
    def __init__(self, master, status: StatusBar, **kw):
        super().__init__(master, bg=DARK, **kw)
        self._status = status
        self._build()

    def _build(self):
        # ── Пароль ──
        pw_card = tk.Frame(self, bg=CARD, relief="flat")
        pw_card.pack(fill="x", padx=16, pady=(16, 6))
        tk.Label(pw_card, text="КЛЮЧ ШИФРОВАНИЯ", font=FONT_UI_SM,
                 bg=CARD, fg=MUTED).pack(anchor="w", padx=12, pady=(8, 2))
        self._pw1 = PasswordEntry(pw_card, "Пароль:")
        self._pw1.pack(fill="x", pady=(0, 4))
        self._pw2 = PasswordEntry(pw_card, "Повторить:")
        self._pw2.pack(fill="x", pady=(0, 8))

        # ── Кнопки (до mid, иначе expand вытесняет) ──
        btn_row = tk.Frame(self, bg=DARK)
        btn_row.pack(fill="x", padx=16, pady=12, side="bottom")
        _btn(btn_row, "🔒  Зашифровать", self._do_encrypt, ACCENT).pack(side="left", padx=(0, 8))
        _btn(btn_row, "📋  Копировать", self._copy, ACCENT2).pack(side="left", padx=(0, 8))
        _btn(btn_row, "📂  Файл…", self._file_encrypt, CARD).pack(side="left")
        _btn(btn_row, "Очистить", self._clear, CARD).pack(side="right")

        # ── Текстовые поля ──
        mid = tk.Frame(self, bg=DARK)
        mid.pack(fill="both", expand=True, padx=16, pady=6)

        tk.Label(mid, text="ИСХОДНЫЙ ТЕКСТ", font=FONT_UI_SM,
                 bg=DARK, fg=MUTED).pack(anchor="w")
        self._input = ScrolledText(mid)
        self._input.pack(fill="both", expand=True, pady=(2, 8))

        tk.Label(mid, text="ЗАШИФРОВАННЫЙ ТОКЕН", font=FONT_UI_SM,
                 bg=DARK, fg=MUTED).pack(anchor="w")
        self._output = ScrolledText(mid, readonly=True)
        self._output.pack(fill="both", expand=True, pady=(2, 0))

    def _do_encrypt(self):
        pw1  = self._pw1.get()
        pw2  = self._pw2.get()
        text = self._input.get_all().strip()
        if not pw1:
            self._status.err("Введите пароль"); return
        if pw1 != pw2:
            self._status.err("Пароли не совпадают"); return
        if not text:
            self._status.err("Введите текст для шифрования"); return
        self._status.info("Генерация ключей…")
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
                    self._status.ok(f"Зашифровано  •  {len(val)} символов в токене")
                else:
                    self._status.err(val)
            except queue.Empty:
                self.after(50, poll)

        threading.Thread(target=work, daemon=True).start()
        self.after(50, poll)

    def _copy(self):
        token = self._output.get_all().strip()
        if not token:
            self._status.err("Нечего копировать"); return
        self.clipboard_clear()
        self.clipboard_append(token)
        self._status.ok("Токен скопирован в буфер обмена")

    def _file_encrypt(self):
        src = filedialog.askopenfilename(title="Выберите файл для шифрования")
        if not src:
            return
        pw1 = self._pw1.get()
        pw2 = self._pw2.get()
        if not pw1:
            self._status.err("Сначала введите пароль"); return
        if pw1 != pw2:
            self._status.err("Пароли не совпадают"); return

        dst = filedialog.asksaveasfilename(
            title="Сохранить зашифрованный файл",
            initialfile=Path(src).stem + ".qc",
            defaultextension=".qc")
        if not dst:
            return

        self._status.info("Шифрование файла…")
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
                    self._status.ok(f"Файл зашифрован → {val}")
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
        self._status.set("Готово")


# ─── Вкладка «Дешифрование» ──────────────────────────────────────────────────

class DecryptTab(tk.Frame):
    def __init__(self, master, status: StatusBar, **kw):
        super().__init__(master, bg=DARK, **kw)
        self._status = status
        self._build()

    def _build(self):
        # ── Пароль ──
        pw_card = tk.Frame(self, bg=CARD)
        pw_card.pack(fill="x", padx=16, pady=(16, 6))
        tk.Label(pw_card, text="КЛЮЧ ДЕШИФРОВКИ", font=FONT_UI_SM,
                 bg=CARD, fg=MUTED).pack(anchor="w", padx=12, pady=(8, 2))
        self._pw = PasswordEntry(pw_card, "Пароль:")
        self._pw.pack(fill="x", pady=(0, 8))

        # ── Кнопки (до mid) ──
        btn_row = tk.Frame(self, bg=DARK)
        btn_row.pack(fill="x", padx=16, pady=12, side="bottom")
        _btn(btn_row, "🔓  Дешифровать", self._do_decrypt, ACCENT).pack(side="left", padx=(0, 8))
        _btn(btn_row, "📋  Вставить", self._paste, ACCENT2).pack(side="left", padx=(0, 8))
        _btn(btn_row, "📂  Файл…", self._file_decrypt, CARD).pack(side="left")
        _btn(btn_row, "Очистить", self._clear, CARD).pack(side="right")

        # ── Текстовые поля ──
        mid = tk.Frame(self, bg=DARK)
        mid.pack(fill="both", expand=True, padx=16, pady=6)

        tk.Label(mid, text="ЗАШИФРОВАННЫЙ ТОКЕН", font=FONT_UI_SM,
                 bg=DARK, fg=MUTED).pack(anchor="w")
        self._input = ScrolledText(mid)
        self._input.pack(fill="both", expand=True, pady=(2, 8))

        tk.Label(mid, text="РАСШИФРОВАННЫЙ ТЕКСТ", font=FONT_UI_SM,
                 bg=DARK, fg=MUTED).pack(anchor="w")
        self._output = ScrolledText(mid, readonly=True)
        self._output.pack(fill="both", expand=True, pady=(2, 0))

    def _do_decrypt(self):
        pw    = self._pw.get()
        token = self._input.get_all().replace("\n", "").strip()
        if not pw:
            self._status.err("Введите пароль"); return
        if not token:
            self._status.err("Вставьте токен для дешифровки"); return
        self._status.info("Восстановление ключей…")
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
                    self._status.ok(f"Дешифровано  •  {len(val)} символов")
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
            self._status.ok("Вставлено из буфера обмена")
        except tk.TclError:
            self._status.err("Буфер обмена пуст")

    def _file_decrypt(self):
        src = filedialog.askopenfilename(
            title="Выберите зашифрованный файл",
            filetypes=[("Aegis files", "*.qc"), ("All files", "*.*")])
        if not src:
            return
        pw = self._pw.get()
        if not pw:
            self._status.err("Сначала введите пароль"); return

        dst = filedialog.asksaveasfilename(
            title="Сохранить расшифрованный файл",
            initialfile=Path(src).stem)
        if not dst:
            return

        self._status.info("Дешифровка файла…")
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
                    self._status.ok(f"Файл дешифрован → {val}")
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
        self._status.set("Готово")


# ─── Главное окно ────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Aegis — Шифровальщик")
        self.geometry("860x820")
        self.minsize(700, 700)
        self.configure(bg=DARK)

        try:
            self.iconbitmap(default="")
        except Exception:
            pass

        self._build()

    def _build(self):
        # ── Заголовок ──
        header = tk.Frame(self, bg=PANEL, height=52)
        header.pack(fill="x")
        header.pack_propagate(False)

        title_frame = tk.Frame(header, bg=PANEL)
        title_frame.pack(side="left", padx=18, pady=8)
        tk.Label(title_frame, text="🔐 Aegis", font=("Segoe UI", 14, "bold"),
                 bg=PANEL, fg=TEXT).pack(side="left")
        tk.Label(title_frame, text="  v1.0",
                 font=FONT_UI_SM, bg=PANEL, fg=MUTED).pack(side="left", pady=2)

        badge = tk.Frame(header, bg=ACCENT, padx=8, pady=3)
        badge.pack(side="right", padx=18, pady=12)
        tk.Label(badge, text="AES-256 · ChaCha20 · Argon2id",
                 font=FONT_UI_SM, bg=ACCENT, fg=TEXT).pack()

        _separator(self).pack(fill="x")

        # ── Стиль вкладок ──
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TNotebook",
                        background=DARK, borderwidth=0, tabmargins=0)
        style.configure("TNotebook.Tab",
                        background=PANEL, foreground=MUTED,
                        font=FONT_HEAD, padding=(18, 8),
                        borderwidth=0, focuscolor=DARK)
        style.map("TNotebook.Tab",
                  background=[("selected", DARK)],
                  foreground=[("selected", TEXT)])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        # ── Статус-бар ──
        self._status = StatusBar(self)
        self._status.pack(fill="x", side="bottom")
        _separator(self).pack(fill="x", side="bottom")

        # ── Вкладки ──
        self._enc_tab = EncryptTab(nb, self._status)
        self._dec_tab = DecryptTab(nb, self._status)

        nb.add(self._enc_tab, text="  🔒  Шифрование  ")
        nb.add(self._dec_tab, text="  🔓  Дешифровка  ")


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
