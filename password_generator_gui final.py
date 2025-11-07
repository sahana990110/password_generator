import tkinter as tk
from tkinter import ttk, messagebox
import string
import random
import math
from datetime import datetime

try:
    import pyperclip
    HAS_PYPERCLIP = True
except Exception:
    HAS_PYPERCLIP = False


SIMILAR_LOOKALIKES = set("O0oIl1|`'\";:,.~")


def build_character_pool(include_uppercase: bool, include_digits: bool, include_specials: bool, exclude_similar: bool) -> str:
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase if include_uppercase else ""
    digits = string.digits if include_digits else ""
    special_characters = "!@#$%^&*()_+-=[]{}|;:,.<>?" if include_specials else ""
    pool = lowercase_letters + uppercase_letters + digits + special_characters
    if exclude_similar:
        pool = ''.join(ch for ch in pool if ch not in SIMILAR_LOOKALIKES)
    return pool


def generate_password(length: int,
                      include_uppercase: bool,
                      include_digits: bool,
                      include_specials: bool,
                      exclude_similar: bool,
                      ensure_all_types: bool) -> str:
    pool = build_character_pool(include_uppercase, include_digits, include_specials, exclude_similar)
    if not pool:
        raise ValueError("Character pool is empty. Enable at least one category.")

    required_chars = []
    if ensure_all_types:
        required_chars.append(random.choice([c for c in string.ascii_lowercase if c in pool]))
        if include_uppercase:
            required_chars.append(random.choice([c for c in string.ascii_uppercase if c in pool]))
        if include_digits:
            required_chars.append(random.choice([c for c in string.digits if c in pool]))
        if include_specials:
            specials = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            required_chars.append(random.choice([c for c in specials if c in pool]))

    if length < len(required_chars):
        raise ValueError("Length too short for selected requirements.")

    remaining = length - len(required_chars)
    rest = [random.choice(pool) for _ in range(remaining)]
    chars = required_chars + rest
    random.shuffle(chars)
    return ''.join(chars)


def estimate_strength(length: int, include_uppercase: bool, include_digits: bool, include_specials: bool) -> str:
    variety = 1
    if include_uppercase:
        variety += 1
    if include_digits:
        variety += 1
    if include_specials:
        variety += 1
    if length < 8 or variety <= 2:
        return "Weak"
    if 8 <= length < 12 and variety >= 2:
        return "Medium"
    if length >= 12 and variety >= 3:
        return "Strong"
    return "Medium"


def entropy_bits(length: int, charset_size: int) -> float:
    if length <= 0 or charset_size <= 0:
        return 0.0
    return length * math.log2(charset_size)


def save_password_history(entries, history_path: str = "password_history.txt") -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(history_path, "a", encoding="utf-8") as f:
        for e in entries:
            f.write(f"[{ts}] {e['password']} | strength={e['strength']} | entropy_bits={e['entropy']:.2f} | charset={e['charset']}\n")


class PasswordGeneratorGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Password Generator")
        self.root.geometry("640x520")

        self.length_var = tk.IntVar(value=12)
        self.upper_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.specials_var = tk.BooleanVar(value=True)
        self.exclude_similar_var = tk.BooleanVar(value=False)
        self.ensure_types_var = tk.BooleanVar(value=True)
        self.count_var = tk.IntVar(value=1)

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=12)
        top.pack(fill="x")

        title = ttk.Label(top, text="Password Generator", font=("Segoe UI", 14, "bold"))
        title.pack(side="left")

        # Options frame
        opts = ttk.LabelFrame(self.root, text="Options", padding=12)
        opts.pack(fill="x", padx=12, pady=(6, 0))

        # Length
        row_len = ttk.Frame(opts)
        row_len.pack(fill="x", pady=4)
        ttk.Label(row_len, text="Length:").pack(side="left")
        scale = ttk.Scale(row_len, from_=4, to=64, orient="horizontal", command=self._on_scale)
        scale.set(self.length_var.get())
        scale.pack(side="left", fill="x", expand=True, padx=8)
        self.length_label = ttk.Label(row_len, text=str(self.length_var.get()))
        self.length_label.pack(side="left")

        # Toggles
        toggles = ttk.Frame(opts)
        toggles.pack(fill="x", pady=4)
        ttk.Checkbutton(toggles, text="Uppercase", variable=self.upper_var, command=self._update_strength).pack(side="left", padx=6)
        ttk.Checkbutton(toggles, text="Numbers", variable=self.digits_var, command=self._update_strength).pack(side="left", padx=6)
        ttk.Checkbutton(toggles, text="Specials", variable=self.specials_var, command=self._update_strength).pack(side="left", padx=6)
        ttk.Checkbutton(toggles, text="Exclude similar (O/0, l/I)", variable=self.exclude_similar_var, command=self._update_strength).pack(side="left", padx=6)

        # Ensure types and count
        row_extra = ttk.Frame(opts)
        row_extra.pack(fill="x", pady=4)
        ttk.Checkbutton(row_extra, text="Ensure at least one of each selected type", variable=self.ensure_types_var).pack(side="left")
        ttk.Label(row_extra, text="Count:").pack(side="left", padx=(12, 4))
        count_entry = ttk.Entry(row_extra, textvariable=self.count_var, width=6)
        count_entry.pack(side="left")

        # Strength and entropy
        stats = ttk.LabelFrame(self.root, text="Strength", padding=12)
        stats.pack(fill="x", padx=12, pady=6)
        self.strength_value = ttk.Label(stats, text="-")
        self.strength_value.pack(side="left")
        self.entropy_value = ttk.Label(stats, text="", foreground="#666")
        self.entropy_value.pack(side="right")

        # Buttons
        actions = ttk.Frame(self.root, padding=12)
        actions.pack(fill="x")
        gen_btn = ttk.Button(actions, text="Generate", command=self.on_generate)
        gen_btn.pack(side="left")
        copy_btn = ttk.Button(actions, text="Copy selected", command=self.on_copy)
        copy_btn.pack(side="left", padx=8)
        save_btn = ttk.Button(actions, text="Save history", command=self.on_save)
        save_btn.pack(side="left")
        quit_btn = ttk.Button(actions, text="Quit", command=self.root.quit)
        quit_btn.pack(side="right")

        # Results area
        results_frame = ttk.LabelFrame(self.root, text="Generated Passwords", padding=8)
        results_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.results = tk.Listbox(results_frame, font=("Consolas", 11))
        self.results.pack(fill="both", expand=True)

        self._update_strength()

    def _on_scale(self, value):
        self.length_var.set(int(float(value)))
        self.length_label.config(text=str(self.length_var.get()))
        self._update_strength()

    def _update_strength(self):
        length = self.length_var.get()
        inc_up = self.upper_var.get()
        inc_dg = self.digits_var.get()
        inc_sp = self.specials_var.get()
        pool = build_character_pool(inc_up, inc_dg, inc_sp, self.exclude_similar_var.get())
        ent = entropy_bits(length, len(pool))
        self.strength_value.config(text=f"{estimate_strength(length, inc_up, inc_dg, inc_sp)}")
        self.entropy_value.config(text=f"Entropy: {ent:.2f} bits | Charset: {len(pool)}")

    def on_generate(self):
        try:
            length = self.length_var.get()
            count = self.count_var.get()
            if count <= 0 or count > 100:
                messagebox.showerror("Invalid count", "Count must be between 1 and 100.")
                return

            inc_up = self.upper_var.get()
            inc_dg = self.digits_var.get()
            inc_sp = self.specials_var.get()
            exc_sim = self.exclude_similar_var.get()
            ens_all = self.ensure_types_var.get()

            pool = build_character_pool(inc_up, inc_dg, inc_sp, exc_sim)
            charset = len(pool)
            ent = entropy_bits(length, charset)
            self.results.delete(0, tk.END)
            for _ in range(count):
                pwd = generate_password(length, inc_up, inc_dg, inc_sp, exc_sim, ens_all)
                self.results.insert(tk.END, pwd)

            self.strength_value.config(text=f"{estimate_strength(length, inc_up, inc_dg, inc_sp)}")
            self.entropy_value.config(text=f"Entropy: {ent:.2f} bits | Charset: {charset}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_copy(self):
        if not HAS_PYPERCLIP:
            messagebox.showinfo("Clipboard", "Install 'pyperclip' to enable copying (pip install pyperclip).")
            return
        sel = self.results.curselection()
        if not sel:
            messagebox.showinfo("Copy", "Select a password from the list to copy.")
            return
        value = self.results.get(sel[0])
        try:
            pyperclip.copy(value)
            messagebox.showinfo("Copy", "Password copied to clipboard.")
        except Exception:
            messagebox.showerror("Copy", "Could not copy to clipboard.")

    def on_save(self):
        items = self.results.get(0, tk.END)
        if not items:
            messagebox.showinfo("Save", "No passwords to save.")
            return
        length = self.length_var.get()
        inc_up = self.upper_var.get()
        inc_dg = self.digits_var.get()
        inc_sp = self.specials_var.get()
        exc_sim = self.exclude_similar_var.get()
        pool = build_character_pool(inc_up, inc_dg, inc_sp, exc_sim)
        charset = len(pool)
        ent = entropy_bits(length, charset)
        strength = estimate_strength(length, inc_up, inc_dg, inc_sp)
        entries = [{"password": p, "entropy": ent, "charset": charset, "strength": strength} for p in items]
        try:
            save_password_history(entries)
            messagebox.showinfo("Save", "Saved to password_history.txt")
        except Exception as e:
            messagebox.showerror("Save", f"Could not save: {e}")


def main():
    root = tk.Tk()
    app = PasswordGeneratorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()


