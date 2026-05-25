"""
Build the SOC Endpoint Agent into a standalone .exe (Windows) or binary (Linux/Mac).

Usage:
    pip install pyinstaller
    python build_endpoint_app.py

Output: dist/SOC-Endpoint-Agent.exe  (Windows)
        dist/SOC-Endpoint-Agent      (Linux/Mac)
"""
import subprocess
import sys
import shutil
from pathlib import Path

ROOT = Path(__file__).parent

def main():
    # Check pyinstaller is available
    if not shutil.which("pyinstaller"):
        print("[ERROR] PyInstaller not found. Install it first:")
        print("        pip install pyinstaller")
        sys.exit(1)

    print("Building SOC Endpoint Agent...")
    print()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "SOC-Endpoint-Agent",
        "--onefile",                      # single executable
        "--windowed",                     # no console window (GUI app)
        "--clean",                        # clean build cache
        "--noconfirm",                    # overwrite existing dist
        "--manifest", str(ROOT / "endpoint_app" / "admin.manifest"),  # require UAC elevation
        # Include the shared + endpoint_agent packages
        "--add-data", f"{ROOT / 'shared'}{SEP}shared",
        "--add-data", f"{ROOT / 'endpoint_agent'}{SEP}endpoint_agent",
        # Hidden imports that PyInstaller might miss
        "--hidden-import", "endpoint_agent.modules",
        "--hidden-import", "endpoint_agent.modules.actions",
        "--hidden-import", "endpoint_agent.modules.auth_logs",
        "--hidden-import", "endpoint_agent.modules.binary_re",
        "--hidden-import", "endpoint_agent.modules.deep_memory",
        "--hidden-import", "endpoint_agent.modules.file_inspect",
        "--hidden-import", "endpoint_agent.modules.memory",
        "--hidden-import", "endpoint_agent.modules.network",
        "--hidden-import", "endpoint_agent.modules.persistence",
        "--hidden-import", "endpoint_agent.modules.processes",
        "--hidden-import", "endpoint_agent.modules.yara_scan",
        "--hidden-import", "shared.schemas",
        "--hidden-import", "shared.config",
        "--hidden-import", "shared.logger",
        "--hidden-import", "httpx",
        "--hidden-import", "pydantic",
        "--hidden-import", "psutil",
        # Entry point
        str(ROOT / "endpoint_app" / "app.py"),
    ]

    result = subprocess.run(cmd, cwd=str(ROOT))

    if result.returncode == 0:
        exe = "SOC-Endpoint-Agent.exe" if sys.platform == "win32" else "SOC-Endpoint-Agent"
        print()
        print("=" * 60)
        print("  Build successful!")
        print(f"  Output: dist/{exe}")
        print()
        print("  Distribute dist/{exe} to endpoint machines.")
        print("  No Python installation required on the endpoint.")
        print("=" * 60)
    else:
        print()
        print("[ERROR] Build failed. Check output above.")
        sys.exit(1)


# Path separator for --add-data (Windows uses ; Linux/Mac uses :)
SEP = ";" if sys.platform == "win32" else ":"

if __name__ == "__main__":
    main()
