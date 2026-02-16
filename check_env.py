import os
import subprocess
import shutil
import json

CONFIG_FILE = "config.json"


def check_binary(name, path):
    print(f"Checking {name}...")
    if not path:
        print(f"  [X] No path set for {name} in config.json")
        return False

    if not os.path.exists(path):
        print(f"  [X] Path does not exist: {path}")
        return False

    if not os.access(path, os.X_OK):
        print(f"  [!] Found file but it's NOT executable. Fixing permissions...")
        try:
            os.chmod(path, 0o755)
            print(f"  [✓] Fixed permissions for {path}")
        except Exception as e:
            print(f"  [X] Failed to fix permissions: {e}")
            return False

    print(f"  [✓] {name} is valid and executable.")
    return True


def run_checks():
    print("=== COCOS DECRYPTOR ENVIRONMENT CHECK ===\n")

    # 1. Check Python dependencies
    try:
        import PyQt5
        print("[✓] PyQt5 is installed.")
    except ImportError:
        print("[X] PyQt5 NOT found. Run: pip3 install PyQt5")

    # 2. Check config.json
    if not os.path.exists(CONFIG_FILE):
        print(f"[!] {CONFIG_FILE} not found. You need to run the app and save settings first.")
        return

    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)

    # 3. Check individual binaries
    results = [
        check_binary("Apktool", config.get("at")),
        check_binary("Reverse", config.get("rv")),
        check_binary("Prettier", config.get("pt"))
    ]

    if all(results):
        print("\n[COMPLETE] Environment is healthy! You are ready to decrypt.")
    else:
        print("\n[FAILED] Please fix the errors above before running.")


if __name__ == "__main__":
    run_checks()