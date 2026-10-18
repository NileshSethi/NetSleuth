# Document 09: Setup, Execution & Troubleshooting Guide

## 1. Overview
This guide provides complete, step-by-step instructions for configuring the local environment, managing dependencies, launching the NetSleuth Streamlit application, executing test suites, and troubleshooting common errors on Windows, macOS, and Linux.

> **Note on Project Status:**  
> In Phase 1, only placeholder interfaces and documentation exist. The installation steps below will become operational once requirements are installed in Phase 2.

---

## 2. Environment Verification & Setup

### Step 1: Verify Python Installation
NetSleuth requires Python 3.10, 3.11, or 3.12. Verify your active version:

**Windows (PowerShell or Command Prompt):**
```powershell
python --version
```
*Expected output:* `Python 3.10.x` (or 3.11.x / 3.12.x).

**macOS / Linux:**
```bash
python3 --version
```

### Step 2: Confirm Active Directory
Ensure your terminal is located directly in the project root:

**Windows:**
```powershell
pwd
# Must show: ...\NetSleuth
```

**macOS / Linux:**
```bash
pwd
# Must show: .../NetSleuth
```

---

## 3. Creating & Activating Virtual Environment

Using an isolated virtual environment prevents library version conflicts.

### Windows (PowerShell)
```powershell
# Create the virtual environment named .venv
python -m venv .venv

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1
```

*Note for Windows:* If you receive an execution policy error (`script is disabled on this system`), run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\.venv\Scripts\Activate.ps1
```

### macOS / Linux (Bash / Zsh)
```bash
# Create the virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate
```

*(Once activated, your terminal prompt will show `(.venv)`).*

---

## 4. Installing Dependencies

Upgrade `pip` and install the package requirements:

```bash
# Upgrade pip
pip install --upgrade pip

# Install runtime dependencies
pip install -r requirements.txt

# Install development & testing dependencies
pip install -r requirements-dev.txt
```

---

## 5. Running the Application & Test Suite

### Running the Streamlit Web Application
Once implemented, launch the web dashboard using:
```bash
streamlit run app.py
```
Streamlit will start a local server and output:
```text
  Local URL: http://localhost:8501
  Network URL: http://192.168.x.x:8501
```
Open `http://localhost:8501` in your web browser.

### Running Automated Tests
Run unit tests with verbose output:
```bash
pytest -v
```

Run test suite with code coverage:
```bash
pytest --cov=src/netsleuth -v
```

### Code Formatting and Linting
Check code quality using Ruff:
```bash
ruff check .
```

---

## 6. Common Issues & Troubleshooting

### Issue 1: `ModuleNotFoundError: No module named 'netsleuth'`
- **Cause:** Python cannot locate the `src` directory on its module search path (`sys.path`).
- **Fix:** In PowerShell or Bash, set `PYTHONPATH`:
  - **Windows (PowerShell):** `$env:PYTHONPATH = "src"`
  - **macOS / Linux:** `export PYTHONPATH=src`
  - *Alternatively:* NetSleuth entry points (`app.py`) dynamically append `src` to `sys.path`.

### Issue 2: `Streamlit: command not found`
- **Cause:** The virtual environment is not activated, or `requirements.txt` was not installed in the active environment.
- **Fix:** Verify `(.venv)` is visible in your terminal, then re-run `pip install -r requirements.txt`.

### Issue 3: Git Tracking Unwanted Files
- **Cause:** Files were created before `.gitignore` was configured.
- **Fix:** Verify ignore rules using:
  ```bash
  git check-ignore -v <path_to_file>
  ```
  If an ignored file was already committed, untrack it without deleting local data:
  ```bash
  git rm --cached <path_to_file>
  ```

### Issue 4: `PermissionError` when writing outputs
- **Cause:** Terminal process lacks write permissions to `data/` or `reports/`.
- **Fix:** Ensure you are running with normal user permissions in your user home directory rather than a restricted system directory.
