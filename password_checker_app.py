"""Desktop application for the local Password Strength Checker."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox
from typing import Any, cast

from password_checker import PasswordAnalysis, analyze_password

WINDOW_WIDTH = 640
WINDOW_HEIGHT = 540
WINDOW_TITLE = "Password Checker.exe"

BG = "#eeeeee"
PANEL_BG = "#f7f7f7"
TEXT = "#111111"
MUTED = "#555555"
BORDER = "#9b9b9b"
GOOD = "#168a2e"
BAD = "#b3261e"
WARNING = "#b45f06"
VERY_WEAK = "#b3261e"
VERY_STRONG = "#147a28"

STRENGTH_COLORS = {
    "Very Weak": VERY_WEAK,
    "Weak": BAD,
    "Moderate": WARNING,
    "Strong": GOOD,
    "Very Strong": VERY_STRONG,
}

CHECK_ROWS = (
    ("Lowercase", "has_lowercase"),
    ("Uppercase", "has_uppercase"),
    ("Digits", "has_digit"),
    ("Special characters", "has_special"),
)


def ui_summary(analysis: PasswordAnalysis) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    """Return presentation-only data without exposing the password."""
    findings = analysis.findings or ("No major weaknesses found.",)
    suggestions = analysis.suggestions or ("You're good to go!",)
    return analysis.level, findings, suggestions


class PasswordCheckerApp:
    """Small native-looking Tkinter interface around the tested analysis engine."""

    def __init__(self, root: tk.Tk | tk.Toplevel) -> None:
        self.root = root
        self.root.title(WINDOW_TITLE)
        self.root.configure(bg=BG)
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.root.minsize(600, 500)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(3, weight=1)
        self.showing_password = False

        default_font = ("Segoe UI", 10)
        self.heading_font = ("Segoe UI", 11, "bold")
        self.title_font = ("Segoe UI", 15, "bold")
        root_options = cast(Any, self.root)
        root_options.option_add("*Font", default_font)
        root_options.option_add("*Button.Font", default_font)
        root_options.option_add("*Label.Font", default_font)
        self._build_ui()
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.root.minsize(WINDOW_WIDTH, WINDOW_HEIGHT)
        self.root.bind("<Return>", self._on_check)
        self.root.bind("<Escape>", self._on_clear)
        self.password_entry.focus_set()

    def center_window(self) -> None:
        """Place the initial window at the center of the available screen."""
        width = WINDOW_WIDTH
        height = WINDOW_HEIGHT
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = max((screen_width - width) // 2, 0)
        y = max((screen_height - height) // 2, 0)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.update_idletasks()

    def _build_ui(self) -> None:
        self.main = tk.Frame(self.root, bg=BG, padx=18, pady=16)
        self.main.grid(row=0, column=0, rowspan=5, sticky="nsew")
        self.main.columnconfigure(0, weight=1)
        self.main.rowconfigure(3, weight=1)

        tk.Label(
            self.main,
            text="Enter password:",
            bg=BG,
            fg=TEXT,
            font=self.heading_font,
            anchor="w",
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 7))

        input_frame = tk.Frame(self.main, bg=BG)
        input_frame.grid(row=1, column=0, columnspan=3, sticky="ew")
        input_frame.columnconfigure(0, weight=1)

        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(
            input_frame,
            textvariable=self.password_var,
            show="•",
            relief="sunken",
            borderwidth=2,
            highlightthickness=1,
            highlightcolor=BORDER,
            bg="white",
            fg=TEXT,
            insertbackground=TEXT,
        )
        self.password_entry.grid(row=0, column=0, sticky="ew", ipady=7)

        self.eye_button = tk.Button(
            input_frame,
            text="👁",
            command=self._toggle_visibility,
            width=3,
            height=1,
            relief="raised",
            borderwidth=2,
            takefocus=True,
            cursor="hand2",
        )
        self.eye_button.grid(row=0, column=1, padx=(10, 10), ipady=1)
        self.eye_button.bind("<Return>", lambda _event: self._toggle_visibility())

        self.check_button = tk.Button(
            input_frame,
            text="Check",
            command=self._on_check,
            width=11,
            relief="raised",
            borderwidth=2,
            default="active",
            takefocus=True,
        )
        self.check_button.grid(row=0, column=2, ipady=3)

        self.result_panel = tk.Frame(
            self.main,
            bg=PANEL_BG,
            highlightbackground=BORDER,
            highlightthickness=1,
            padx=15,
            pady=12,
        )
        self.result_panel.grid(row=2, column=0, columnspan=3, sticky="nsew", pady=(14, 12))
        self.result_panel.columnconfigure(0, weight=1)
        self.result_panel.columnconfigure(1, weight=1)

        strength_line = tk.Frame(self.result_panel, bg=PANEL_BG)
        strength_line.grid(row=0, column=0, columnspan=2, sticky="w")

        tk.Label(
            strength_line,
            text="Strength:",
            bg=PANEL_BG,
            fg=TEXT,
            font=("Segoe UI", 14, "bold"),
        ).pack(side="left")

        self.strength_value_label = tk.Label(
            strength_line,
            text="—",
            bg=PANEL_BG,
            fg=TEXT,
            font=("Segoe UI", 14, "bold"),
        )
        self.strength_value_label.pack(side="left", padx=(6, 0))

        self.score_label = tk.Label(
            self.result_panel,
            text="Score: — / 100",
            bg=PANEL_BG,
            fg=TEXT,
            font=("Segoe UI", 11),
            anchor="w",
        )
        self.score_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(7, 0))

        self.length_label = tk.Label(
            self.result_panel,
            text="Length: —",
            bg=PANEL_BG,
            fg=TEXT,
            font=("Segoe UI", 11),
            anchor="w",
        )
        self.length_label.grid(row=2, column=0, columnspan=2, sticky="w", pady=(2, 0))

        self.check_widgets: list[tuple[tk.Label, tk.Label]] = []
        self.check_container = tk.Frame(self.result_panel, bg=PANEL_BG)
        self.check_container.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10, 5))
        self.check_container.columnconfigure(0, weight=1)
        self.check_container.columnconfigure(1, weight=1)

        for index, (label_text, attribute) in enumerate(CHECK_ROWS):
            column = 0 if index < 2 else 1
            row = index if index < 2 else index - 2
            cell = tk.Frame(self.check_container, bg=PANEL_BG)
            cell.grid(row=row, column=column, sticky="w", pady=2, padx=(0, 12))
            icon = tk.Label(
                cell,
                text="—",
                bg=PANEL_BG,
                fg=MUTED,
                font=("Segoe UI", 12, "bold"),
                width=2,
                anchor="w",
            )
            label = tk.Label(
                cell,
                text=label_text,
                bg=PANEL_BG,
                fg=TEXT,
                anchor="w",
            )
            icon.pack(side="left")
            label.pack(side="left")
            self.check_widgets.append((icon, label))
            setattr(self, f"_class_attr_{index}", attribute)

        separator = tk.Frame(self.result_panel, bg=BORDER, height=1)
        separator.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(5, 9))

        tk.Label(
            self.result_panel,
            text="Findings:",
            bg=PANEL_BG,
            fg=TEXT,
            font=self.heading_font,
            anchor="w",
        ).grid(row=5, column=0, columnspan=2, sticky="w")

        self.findings_text = tk.Label(
            self.result_panel,
            text="• —",
            bg=PANEL_BG,
            fg=TEXT,
            justify="left",
            anchor="nw",
            wraplength=570,
        )
        self.findings_text.grid(row=6, column=0, columnspan=2, sticky="nw", pady=(3, 7))

        tk.Label(
            self.result_panel,
            text="Suggestions:",
            bg=PANEL_BG,
            fg=TEXT,
            font=self.heading_font,
            anchor="w",
        ).grid(row=7, column=0, columnspan=2, sticky="w")

        self.suggestions_text = tk.Label(
            self.result_panel,
            text="• —",
            bg=PANEL_BG,
            fg=TEXT,
            justify="left",
            anchor="nw",
            wraplength=570,
        )
        self.suggestions_text.grid(row=8, column=0, columnspan=2, sticky="nw", pady=(3, 0))

        button_frame = tk.Frame(self.main, bg=BG)
        button_frame.grid(row=3, column=0, columnspan=3, sticky="ew")
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)

        self.clear_button = tk.Button(
            button_frame,
            text="Clear",
            command=self._on_clear,
            width=11,
            relief="raised",
            borderwidth=2,
        )
        self.clear_button.grid(row=0, column=0, sticky="w", ipady=3)

        self.close_button = tk.Button(
            button_frame,
            text="Close",
            command=self.root.destroy,
            width=11,
            relief="raised",
            borderwidth=2,
        )
        self.close_button.grid(row=0, column=1, sticky="e", ipady=3)

    def _toggle_visibility(self) -> None:
        self.showing_password = not self.showing_password
        self.password_entry.configure(show="" if self.showing_password else "•")

    def _on_check(self, _event: object | None = None) -> str:
        password = self.password_var.get()
        try:
            analysis = analyze_password(password)
        except Exception:
            # The detailed exception must never be displayed because it could
            # unexpectedly contain sensitive input.
            messagebox.showerror(
                "Password Checker",
                "Could not analyze the password safely.",
                parent=self.root,
            )
            return "break"

        self._display_analysis(analysis)
        return "break"

    def _display_analysis(self, analysis: PasswordAnalysis) -> None:
        level, findings, suggestions = ui_summary(analysis)
        strength_color = STRENGTH_COLORS.get(level, TEXT)

        self.strength_value_label.configure(
            text=level,
            fg=strength_color,
        )
        self.score_label.configure(text=f"Score: {analysis.score} / 100")
        self.length_label.configure(text=f"Length: {analysis.length}")

        values = (
            analysis.has_lowercase,
            analysis.has_uppercase,
            analysis.has_digit,
            analysis.has_special,
        )
        for (icon, _label), present in zip(self.check_widgets, values):
            icon.configure(
                text="✓" if present else "✗",
                fg=GOOD if present else BAD,
            )

        self.findings_text.configure(
            text="\n".join(f"• {finding}" for finding in findings)
        )
        self.suggestions_text.configure(
            text="\n".join(f"• {suggestion}" for suggestion in suggestions)
        )

    def _on_clear(self, _event: object | None = None) -> str:
        self.password_var.set("")
        self.showing_password = False
        self.password_entry.configure(show="•")
        self.strength_value_label.configure(text="—", fg=TEXT)
        self.score_label.configure(text="Score: — / 100")
        self.length_label.configure(text="Length: —")
        for icon, _label in self.check_widgets:
            icon.configure(text="—", fg=MUTED)
        self.findings_text.configure(text="• —")
        self.suggestions_text.configure(text="• —")
        self.password_entry.focus_set()
        return "break"


def main() -> int:
    try:
        root = tk.Tk()
        root.withdraw()
        PasswordCheckerApp(root).center_window()
        root.deiconify()
    except tk.TclError:
        print("Password Checker could not start the desktop interface.")
        return 1

    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
