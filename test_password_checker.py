# pyright: reportPrivateUsage=false
import random
import time
import unittest
from unittest import mock

import password_checker as checker


class PasswordCheckerTests(unittest.TestCase):
    def test_empty_password(self):
        result = checker.analyze_password("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.level, "Very Weak")
        self.assertEqual(result.length, 0)
        self.assertIn("Password is empty.", result.findings)

    def test_short_password_is_penalized(self):
        result = checker.analyze_password("Ab1!")
        self.assertLessEqual(result.score, 30)
        self.assertIn("Password is very short.", result.findings)

    def test_length_bands(self):
        self.assertEqual(checker._length_points(5), 0)
        self.assertEqual(checker._length_points(6), 15)
        self.assertEqual(checker._length_points(7), 15)
        self.assertEqual(checker._length_points(8), 30)
        self.assertEqual(checker._length_points(11), 30)
        self.assertEqual(checker._length_points(12), 40)
        self.assertEqual(checker._length_points(15), 40)
        self.assertEqual(checker._length_points(16), 50)
        self.assertEqual(checker._length_points(1000), 50)

    def test_long_diverse_password_scores_higher_than_simple_password(self):
        simple = checker.analyze_password("abcdefgh")
        diverse = checker.analyze_password("XqvRk!mN7#pL2zY9")
        self.assertGreater(diverse.score, simple.score)

    def test_highest_strength_band_is_reachable(self):
        result = checker.analyze_password("XqvRk!mN7#pL2zY9")
        self.assertGreaterEqual(result.score, 85)
        self.assertEqual(result.level, "Very Strong")

    def test_character_classes_ascii(self):
        result = checker.analyze_password("Abc123!")
        self.assertTrue(result.has_lowercase)
        self.assertTrue(result.has_uppercase)
        self.assertTrue(result.has_digit)
        self.assertTrue(result.has_special)

    def test_character_classes_unicode(self):
        result = checker.analyze_password("ÀbcЖ12€")
        self.assertTrue(result.has_lowercase)
        self.assertTrue(result.has_uppercase)
        self.assertTrue(result.has_digit)
        self.assertTrue(result.has_special)

    def test_common_password_is_capped(self):
        result = checker.analyze_password("password")
        self.assertLessEqual(result.score, 24)
        self.assertIn("common weak-password", " ".join(result.findings))

    def test_common_password_case_insensitive(self):
        result = checker.analyze_password("PaSsWoRd")
        self.assertLessEqual(result.score, 24)

    def test_common_password_trivial_numeric_variants_are_detected(self):
        for password in ("password123", "PASSWORD12!", "1234567", "qwerty2026"):
            with self.subTest(password=password):
                result = checker.analyze_password(password)
                self.assertLessEqual(result.score, 24)
                self.assertIn("common weak-password", " ".join(result.findings))

    def test_common_password_trivial_symbol_decorations_are_detected(self):
        for password in ("password!!!", "!qwerty!", "admin@@"):
            with self.subTest(password=password):
                result = checker.analyze_password(password)
                self.assertLessEqual(result.score, 24)

    def test_common_password_compact_form_detects_separator_decorations(self):
        self.assertTrue(checker._contains_common_password("pass-word"))
        self.assertTrue(checker._contains_common_password("qwerty-123"))
        self.assertFalse(checker._contains_common_password("passwordManager!42"))

    def test_common_password_detector_does_not_use_unbounded_dictionary_matching(self):
        self.assertFalse(checker._contains_common_password("passwordful"))
        self.assertFalse(checker._contains_common_password("administrator"))

    def test_sequence_ascending(self):
        result = checker.analyze_password("abcDEF123!")
        self.assertIn("ascending or descending sequence", " ".join(result.findings))

    def test_sequence_descending(self):
        result = checker.analyze_password("987zyx!Abc")
        self.assertIn("ascending or descending sequence", " ".join(result.findings))

    def test_sequence_requires_contiguous_ascii_alphanumeric_data(self):
        self.assertFalse(checker._has_sequence("a-b-c"))
        self.assertFalse(checker._has_sequence("αβγ"))
        self.assertFalse(checker._has_sequence("١٢٣"))
        self.assertFalse(checker._has_sequence("🙂🙃😶"))

    def test_sequence_does_not_casefold_non_ascii_into_ascii(self):
        self.assertFalse(checker._has_sequence("ßtu"))

    def test_repeated_character_detected(self):
        result = checker.analyze_password("AaaaBC9!")
        self.assertIn("repeated-character", " ".join(result.findings))
        self.assertNotIn("repeated substring", " ".join(result.findings))

    def test_repeated_character_unicode_detected(self):
        self.assertTrue(checker._has_repeated_character_run("€€€abc"))

    def test_repeated_substring_detected(self):
        result = checker.analyze_password("Ab12xyxy!")
        self.assertIn("repeated substring", " ".join(result.findings))

    def test_repeated_substring_ignores_single_character_blocks(self):
        self.assertFalse(checker._has_repeated_substring("aaaa"))
        self.assertTrue(checker._has_repeated_substring("abab"))

    def test_multiple_repeat_blocks_are_one_finding(self):
        result = checker.analyze_password("Abxyxyzzzz123!")
        findings = [item for item in result.findings if "repeated substring" in item]
        self.assertEqual(len(findings), 1)

    def test_repeated_substring_parameter_is_bounded(self):
        self.assertTrue(checker._has_repeated_substring("abcdabcd", max_block_length=4))
        with self.assertRaises(ValueError):
            checker._has_repeated_substring("aaaa", 0)

    def test_keyboard_pattern_detected(self):
        result = checker.analyze_password("Aqwerty9!Zm")
        self.assertIn("keyboard pattern", " ".join(result.findings))

    def test_year_detected_when_standalone(self):
        result = checker.analyze_password("SafePassword2024!")
        self.assertIn("year-like", " ".join(result.findings))

    def test_year_does_not_match_longer_digit_run(self):
        self.assertFalse(checker._contains_year("12024"))
        self.assertFalse(checker._contains_year("20245"))
        self.assertTrue(checker._contains_year("x2024!"))

    def test_score_bounds(self):
        samples = (
            "",
            "a",
            "password",
            "abc123",
            "Abc123!",
            "XqvRk!mN7#pL2zY9",
            "🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂",
        )
        for password in samples:
            result = checker.analyze_password(password)
            self.assertGreaterEqual(result.score, checker.MIN_SCORE)
            self.assertLessEqual(result.score, checker.MAX_SCORE)

    def test_strength_boundaries(self):
        self.assertEqual(checker._strength_level(0), "Very Weak")
        self.assertEqual(checker._strength_level(24), "Very Weak")
        self.assertEqual(checker._strength_level(25), "Weak")
        self.assertEqual(checker._strength_level(44), "Weak")
        self.assertEqual(checker._strength_level(45), "Moderate")
        self.assertEqual(checker._strength_level(69), "Moderate")
        self.assertEqual(checker._strength_level(70), "Strong")
        self.assertEqual(checker._strength_level(84), "Strong")
        self.assertEqual(checker._strength_level(85), "Very Strong")
        self.assertEqual(checker._strength_level(100), "Very Strong")

    def test_score_is_deterministic(self):
        password = "XqvRk!mN7#pL2zY9"
        first = checker.analyze_password(password)
        second = checker.analyze_password(password)
        self.assertEqual(first, second)

    def test_seeded_fuzz_invariants(self):
        rng = random.Random(20260921)
        alphabet = (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!@#$%^&*()_+-=[]{};:',.<>/? \t"
            "🙂€Ж東京"
        )
        for _ in range(1_000):
            length = rng.randrange(0, 100)
            password = "".join(rng.choice(alphabet) for _ in range(length))
            first = checker.analyze_password(password)
            second = checker.analyze_password(password)
            self.assertEqual(first, second)
            self.assertGreaterEqual(first.score, checker.MIN_SCORE)
            self.assertLessEqual(first.score, checker.MAX_SCORE)

    def test_analysis_does_not_contain_password(self):
        password = "Unique-Secret-Value-9821!"
        result = checker.analyze_password(password)
        self.assertNotIn(password, repr(result))
        self.assertNotIn(password, repr(result.findings))
        self.assertNotIn(password, repr(result.suggestions))

    def test_format_report_does_not_echo_password(self):
        password = "Unique-Secret-Value-9821!"
        result = checker.analyze_password(password)
        report = checker.format_report(result)
        self.assertNotIn(password, report)

    def test_report_contains_summary_fields(self):
        result = checker.analyze_password("Abc123!")
        report = checker.format_report(result)
        for label in (
            "Strength:",
            "Score:",
            "Password length:",
            "Lowercase:",
            "Uppercase:",
            "Digits:",
            "Special characters:",
        ):
            with self.subTest(label=label):
                self.assertIn(label, report)

    def test_suggestions_do_not_duplicate(self):
        result = checker.analyze_password("password")
        self.assertEqual(len(result.suggestions), len(set(result.suggestions)))

    def test_missing_class_suggestions(self):
        result = checker.analyze_password("abcdefghijk")
        text = " ".join(result.suggestions)
        self.assertIn("Add uppercase letters.", text)
        self.assertIn("Add digits.", text)
        self.assertIn("Add special characters.", text)

    def test_type_boundary(self):
        with self.assertRaises(TypeError):
            checker.analyze_password(123)  # type: ignore[arg-type]

    def test_invalid_sequence_parameter(self):
        with self.assertRaises(ValueError):
            checker._has_sequence("abc", 1)

    def test_invalid_repeat_parameter(self):
        with self.assertRaises(ValueError):
            checker._has_repeated_character_run("aaa", 1)

    def test_whitespace_is_not_stripped(self):
        result = checker.analyze_password(" Abc123! ")
        self.assertEqual(result.length, 9)
        self.assertTrue(result.has_special)

    def test_unicode_digits_count_as_digits(self):
        result = checker.analyze_password("Ab١٢٣!")
        self.assertTrue(result.has_digit)

    def test_punctuation_only_password_is_special_only(self):
        result = checker.analyze_password("!!!!!!!!")
        self.assertFalse(result.has_lowercase)
        self.assertFalse(result.has_uppercase)
        self.assertFalse(result.has_digit)
        self.assertTrue(result.has_special)

    def test_mixed_scripts_do_not_crash(self):
        result = checker.analyze_password("AaБб12!東京")
        self.assertIsInstance(result.score, int)

    def test_emoji_and_combining_marks_do_not_crash(self):
        self.assertIsInstance(checker.analyze_password("Abc123!🙂🙂").score, int)
        self.assertIsInstance(checker.analyze_password("A\u0301bc123!").score, int)

    def test_control_characters_do_not_crash(self):
        result = checker.analyze_password("Ab1!\x00\x01")
        self.assertIsInstance(result.score, int)

    def test_very_long_input_is_processed(self):
        password = "Ab1!" * 10_000
        result = checker.analyze_password(password)
        self.assertGreaterEqual(result.score, 0)
        self.assertLessEqual(result.score, 100)

    def test_large_input_does_not_make_substring_detection_quadratic(self):
        password = "Aa0!x" * 200_000
        start = time.perf_counter()
        result = checker.analyze_password(password)
        elapsed = time.perf_counter() - start
        self.assertIsInstance(result.score, int)
        self.assertLess(elapsed, 5.0)

    def test_main_success_path_is_secret_safe(self):
        password = "Abcd1234!xyz"
        with mock.patch.object(checker.getpass, "getpass", return_value=password):
            with mock.patch("builtins.print") as print_mock:
                code = checker.main()
        self.assertEqual(code, 0)
        printed = "\n".join(str(call.args[0]) for call in print_mock.call_args_list if call.args)
        self.assertNotIn(password, printed)
        self.assertIn("Strength:", printed)

    def test_main_keyboard_interrupt_is_safe(self):
        with mock.patch.object(checker.getpass, "getpass", side_effect=KeyboardInterrupt):
            with mock.patch("builtins.print") as print_mock:
                code = checker.main()
        self.assertEqual(code, 130)
        printed = "\n".join(str(call.args[0]) for call in print_mock.call_args_list if call.args)
        self.assertEqual(printed, "\nOperation cancelled.")

    def test_main_safe_error_message(self):
        with mock.patch.object(
            checker.getpass, "getpass", side_effect=RuntimeError("secret failure")
        ):
            with mock.patch("builtins.print") as print_mock:
                code = checker.main()
        self.assertEqual(code, 1)
        printed = "\n".join(str(call.args[0]) for call in print_mock.call_args_list if call.args)
        self.assertIn("Could not analyze the password safely.", printed)
        self.assertNotIn("secret failure", printed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
