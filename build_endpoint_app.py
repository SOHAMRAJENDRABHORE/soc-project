"""
Build the SOC Endpoint Agent into a standalone binary.

  Windows → dist/SOC-Endpoint-Agent.exe  (run on any Windows machine, no Python needed)
  Linux   → dist/SOC-Endpoint-Agent      (run on any Linux machine, no Python needed)
  macOS   → dist/SOC-Endpoint-Agent      (run on any macOS machine, no Python needed)

IMPORTANT: PyInstaller cannot cross-compile.
  Build on Windows  → you get the Windows .exe
  Build on Linux    → you get the Linux binary
  Build on macOS    → you get the macOS binary

Usage:
    pip install pyinstaller
    python build_endpoint_app.py

Linux prerequisites (tkinter):
    sudo apt install python3-tk      # Debian/Ubuntu
    sudo dnf install python3-tkinter # Fedora/RHEL
"""
import subprocess
import sys
import shutil
from pathlib import Path

IS_WIN   = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_MAC   = sys.platform == "darwin"

# --add-data separator
SEP = ";" if IS_WIN else ":"

ROOT = Path(__file__).parent


def main():
    if not shutil.which("pyinstaller"):
        print("[ERROR] PyInstaller not found. Run:  pip install pyinstaller")
        sys.exit(1)

    platform_name = "Windows" if IS_WIN else "Linux" if IS_LINUX else "macOS"
    exe_name = "SOC-Endpoint-Agent.exe" if IS_WIN else "SOC-Endpoint-Agent"
    print(f"Building SOC Endpoint Agent for {platform_name}...")
    print()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "SOC-Endpoint-Agent",
        "--onefile",
        "--clean",
        "--noconfirm",
        # Include shared + endpoint_agent source packages
        "--add-data", f"{ROOT / 'shared'}{SEP}shared",
        "--add-data", f"{ROOT / 'endpoint_agent'}{SEP}endpoint_agent",
        # Hidden imports
        "--hidden-import", "endpoint_agent.modules",
        "--hidden-import", "endpoint_agent.modules.actions",
        "--hidden-import", "endpoint_agent.modules.auth_logs",
        "--hidden-import", "endpoint_agent.modules.binary_re",
        "--hidden-import", "endpoint_agent.modules.deep_memory",
        "--hidden-import", "endpoint_agent.modules.file_inspect",
        "--hidden-import", "endpoint_agent.modules.file_watcher",
        "--hidden-import", "endpoint_agent.modules.memory",
        "--hidden-import", "endpoint_agent.modules.network",
        "--hidden-import", "endpoint_agent.modules.persistence",
        "--hidden-import", "endpoint_agent.modules.process_monitor",
        "--hidden-import", "endpoint_agent.modules.processes",
        "--hidden-import", "endpoint_agent.modules.yara_scan",
        "--hidden-import", "endpoint_agent.watcher",
        "--hidden-import", "shared.schemas",
        "--hidden-import", "shared.config",
        "--hidden-import", "shared.logger",
        "--hidden-import", "httpx",
        "--hidden-import", "pydantic",
        "--hidden-import", "psutil",
        "--hidden-import", "volatility3",
        "--hidden-import", "volatility3.framework",
        "--hidden-import", "volatility3.plugins",
        "--hidden-import", "yara",
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "tkinter.scrolledtext",
        "--hidden-import", "tkinter.filedialog",
        "--hidden-import", "tkinter.messagebox",
    ]

    # Windows-only flags
    if IS_WIN:
        cmd += [
            "--windowed",   # no console window
            "--manifest", str(ROOT / "endpoint_app" / "admin.manifest"),
        ]
    # Linux: keep console visible so users can see errors if tkinter fails
    # macOS: --windowed works fine
    if IS_MAC:
        cmd.append("--windowed")

    cmd.append(str(ROOT / "endpoint_app" / "app.py"))

    result = subprocess.run(cmd, cwd=str(ROOT))

    if result.returncode == 0:
        print()
        print("=" * 60)
        print(f"  Build successful! ({platform_name})")
        print(f"  Output: dist/{exe_name}")
        print()
        print("  Copy dist/{} to any {} endpoint machine.".format(exe_name, platform_name))
        print("  No Python installation required on the endpoint.")
        if IS_LINUX:
            print()
            print("  Linux note: endpoint needs libGL / Tk runtime libs.")
            print("  If it crashes, run:  sudo apt install python3-tk libgl1")
        print("=" * 60)
    else:
        print()
        print("[ERROR] Build failed. Check output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
