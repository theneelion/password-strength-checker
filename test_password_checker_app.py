from __future__ import annotations
# pyright: reportPrivateUsage=false
import tkinter as tk
import unittest
from unittest import mock

import password_checker as checker
import password_checker_app as app_module


def widget_text(root: tk.Misc) -> str:
    values: list[str] = []

    def visit(widget: tk.Misc) -> None:
        try:
            for option in ("text",):
                value = widget.cget(option)
                if isinstance(value, str):
                    values.append(value)
        except tk.TclError:
            pass
        for child in widget.winfo_children():
            visit(child)

    visit(root)
    return "\n".join(values)


class PasswordCheckerAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls._tk_root = tk.Tk()
            cls._tk_root.withdraw()
        except tk.TclError as error:
            raise unittest.SkipTest(
                f"Tk/Tcl is unavailable in this environment: {error}"
            ) from error

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tk_root.destroy()

    def setUp(self) -> None:
        self.root = tk.Toplevel(self._tk_root)
        self.root.withdraw()
        self.app = app_module.PasswordCheckerApp(self.root)
        self.root.update_idletasks()

    def tearDown(self) -> None:
        self.root.destroy()

    def test_window_title(self):
        self.assertEqual(self.root.title(), "Password Checker.exe")

    def test_initial_window_is_centered_to_screen(self):
        self.app.center_window()
        geometry = self.root.geometry().split("+")
        width, height = (int(value) for value in geometry[0].split("x"))
        x, y = (int(value) for value in geometry[1:])
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        self.assertEqual(width, app_module.WINDOW_WIDTH)
        self.assertEqual(height, app_module.WINDOW_HEIGHT)
        self.assertEqual(x, (screen_width - width) // 2)
        self.assertEqual(y, (screen_height - height) // 2)

    def test_password_is_masked_by_default(self):
        self.assertEqual(self.app.password_entry.cget("show"), "•")

    def test_show_hide_toggle(self):
        self.app._toggle_visibility()
        self.assertEqual(self.app.password_entry.cget("show"), "")
        self.app._toggle_visibility()
        self.assertEqual(self.app.password_entry.cget("show"), "•")

    def test_check_uses_core_analyzer_and_displays_derived_result(self):
        password = "AqzRk!mN7#pL2vX9"
        expected = checker.analyze_password(password)

        self.app.password_var.set(password)
        self.app._on_check()
        self.root.update_idletasks()

        self.assertIn(expected.level, f"Strength: {self.app.strength_value_label.cget('text')}")
        self.assertEqual(
            self.app.score_label.cget("text"),
            f"Score: {expected.score} / 100",
        )
        self.assertEqual(
            self.app.length_label.cget("text"),
            f"Length: {expected.length}",
        )

    def test_gui_result_does_not_echo_password(self):
        password = "Unique-Desktop-Secret-8271!"
        self.app.password_var.set(password)
        self.app._on_check()
        self.root.update_idletasks()

        displayed = widget_text(self.root)
        self.assertNotIn(password, displayed)

    def test_findings_and_suggestions_are_rendered(self):
        password = "password123"
        self.app.password_var.set(password)
        self.app._on_check()

        displayed = widget_text(self.root)
        self.assertIn("Findings:", displayed)
        self.assertIn("Suggestions:", displayed)
        self.assertIn("common weak-password", displayed)

    def test_no_findings_uses_safe_positive_placeholder(self):
        analysis = checker.PasswordAnalysis(
            score=95,
            level="Very Strong",
            length=20,
            has_lowercase=True,
            has_uppercase=True,
            has_digit=True,
            has_special=True,
            findings=(),
            suggestions=(),
        )
        self.app._display_analysis(analysis)

        self.assertIn("No major weaknesses found.", self.app.findings_text.cget("text"))
        self.assertIn("You're good to go!", self.app.suggestions_text.cget("text"))

    def test_clear_resets_all_derived_display(self):
        self.app.password_var.set("AqzRk!mN7#pL2vX9")
        self.app._on_check()
        self.app._on_clear()

        self.assertEqual(self.app.password_var.get(), "")
        self.assertEqual(self.app.password_entry.cget("show"), "•")
        self.assertEqual(self.app.strength_value_label.cget("text"), "—")
        self.assertEqual(self.app.score_label.cget("text"), "Score: — / 100")
        self.assertEqual(self.app.length_label.cget("text"), "Length: —")
        self.assertEqual(self.app.findings_text.cget("text"), "• —")
        self.assertEqual(self.app.suggestions_text.cget("text"), "• —")

    def test_error_dialog_never_receives_exception_text(self):
        secret = "this-secret-must-not-leak"
        with mock.patch.object(
            app_module,
            "analyze_password",
            side_effect=RuntimeError(secret),
        ), mock.patch.object(app_module.messagebox, "showerror") as showerror:
            self.app.password_var.set(secret)
            self.app._on_check()

        showerror.assert_called_once()
        self.assertNotIn(secret, str(showerror.call_args))

    def test_clear_after_showing_password_restores_mask(self):
        self.app.password_var.set("Abc123!")
        self.app._toggle_visibility()
        self.app._on_clear()
        self.assertEqual(self.app.password_entry.cget("show"), "•")
        self.assertEqual(self.app.password_var.get(), "")

    def test_enter_key_is_bound_to_check(self):
        self.assertTrue(self.root.bind("<Return>"))

    def test_escape_key_is_bound_to_clear(self):
        self.assertTrue(self.root.bind("<Escape>"))


if __name__ == "__main__":
    unittest.main()
