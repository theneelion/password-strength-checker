# Password Strength Checker

A small local Windows desktop application for checking password strength without storing or sending the password.

## Run the desktop app

The desktop application uses these two source files:

```text
password_checker.py
password_checker_app.py
```

Make sure they are in the same folder.

Then run:

```powershell
python password_checker_app.py
```

The application opens as a compact Windows-style password checker.

### Use it

Enter a password into the masked field and click **Check**.

The application shows:

- strength level;
- score out of 100;
- password length;
- lowercase / uppercase / digit / special-character checks;
- detected weaknesses;
- suggestions.

The eye button shows or hides the password in the input field.

**Clear** removes the current password from the input field and resets the displayed result.

Press **Enter** to check and **Escape** to clear.

## Privacy

The checker is local.

It does not:

- store passwords;
- send passwords over a network;
- accept passwords through command-line arguments;
- copy passwords to the clipboard;
- put passwords into result objects;
- display passwords in findings or suggestions.

The desktop interface passes the password only to the local analysis engine in `password_checker.py`.

Python cannot guarantee cryptographic zeroization of immutable strings, so the application avoids unnecessary copies and persistent storage instead of making a false zeroization guarantee.

## Build the Windows EXE

The source application uses only Python's standard library at runtime.

To create:

```text
Password Checker.exe
```

install PyInstaller on Windows:

```powershell
py -3 -m pip install pyinstaller
```

Then run:

```powershell
build_windows.bat
```

The executable will be created at:

```text
dist\Password Checker.exe
```

The generated build files are ignored by Git and should not be committed to the source repository.

### Development environment

A virtual environment is recommended for development and testing, but the packaged Windows executable does not require the project's virtual environment or a separate Python installation to run.

Example:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install pytest pyinstaller
```

The project itself has no third-party runtime dependency; `pytest` and `pyinstaller` are development/build tools.

## Testing

Run the complete test suite:

```powershell
python -m pytest
```

The current test suite contains:

```text
62 tests
```

You can also run the standard-library test runner:

```powershell
python -m unittest discover -s . -p "test_*.py" -v
```

Compile-check the project:

```powershell
python -m py_compile password_checker.py password_checker_app.py test_password_checker.py test_password_checker_app.py
```

The tests cover password-analysis behavior, boundary conditions, Unicode handling, secret non-disclosure, large inputs, performance, CLI error handling, and desktop GUI behavior.

## Project files

```text
password_checker.py
    Deterministic password-analysis engine.

password_checker_app.py
    Desktop application interface.

test_password_checker.py
    Core analysis tests.

test_password_checker_app.py
    Desktop application tests.

build_windows.bat
    Windows EXE build helper.

README.md
    User documentation.

LICENSE
    MIT License.
```

The architecture specifications describe the core engine and desktop application design in more detail.

## Scope

This is a local strength-analysis tool. It does not authenticate users, store credentials, crack passwords, query online breach databases, or guarantee that a password is secure against every possible attack.
