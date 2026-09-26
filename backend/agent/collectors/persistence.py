import os
import sys
import time
from pathlib import Path
from typing import List, Tuple
from agent.models.snapshot import PersistenceItem, CollectorReport
from agent.security.suspicious_items import evaluate_persistence_heuristics

def collect_persistence() -> Tuple[List[PersistenceItem], CollectorReport]:
    t0 = time.time()
    collector_name = "persistence"
    items: List[PersistenceItem] = []
    error_msg = None
    status = "SUCCESS"

    if sys.platform != "win32":
        duration = round((time.time() - t0) * 1000, 2)
        return (items, CollectorReport(collector=collector_name, status="SUCCESS", item_count=0, duration_ms=duration))

    import winreg

    # 1. Registry Run & RunOnce Keys
    reg_targets = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ]

    for root_key, sub_key, location_str in reg_targets:
        try:
            with winreg.OpenKey(root_key, sub_key, 0, winreg.KEY_READ) as key:
                num_values = winreg.QueryInfoKey(key)[1]
                for i in range(num_values):
                    try:
                        vname, vval, _ = winreg.EnumValue(key, i)
                        cmd_str = str(vval)
                        is_sus, reasons = evaluate_persistence_heuristics(vname, location_str, cmd_str)

                        # Attempt to extract file path from command
                        file_path = None
                        cleaned = cmd_str.strip('"\'' )
                        first_token = cleaned.split('"')[0].split(" ")[0]
                        if os.path.exists(first_token):
                            file_path = first_token

                        items.append(PersistenceItem(
                            name=vname,
                            location=location_str,
                            command=cmd_str,
                            file_path=file_path,
                            type="Registry RunKey",
                            is_suspicious=is_sus,
                            suspicious_reasons=reasons
                        ))
                    except Exception:
                        pass
        except FileNotFoundError:
            # Normal: key does not exist on this machine
            pass
        except PermissionError:
            # Restricted key access
            pass
        except Exception as e:
            error_msg = f"Registry query error: {str(e)}"

    # 2. Winlogon Persistence Check (Shell and Userinit)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", 0, winreg.KEY_READ) as key:
            for val_name in ["Shell", "Userinit"]:
                try:
                    val_data, _ = winreg.QueryValueEx(key, val_name)
                    val_str = str(val_data)
                    # Standard Userinit: C:\Windows\system32\userinit.exe,
                    # Standard Shell: explorer.exe
                    is_sus = False
                    reasons = []
                    if val_name == "Shell" and val_str.lower() != "explorer.exe":
                        is_sus = True
                        reasons.append(f"Non-standard Winlogon Shell configured: {val_str}")
                    elif val_name == "Userinit" and not val_str.lower().startswith("c:\\windows\\system32\\userinit.exe"):
                        is_sus = True
                        reasons.append(f"Altered Winlogon Userinit persistence: {val_str}")

                    if is_sus:
                        items.append(PersistenceItem(
                            name=f"Winlogon_{val_name}",
                            location=r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                            command=val_str,
                            type="Winlogon Hijack",
                            is_suspicious=True,
                            suspicious_reasons=reasons
                        ))
                except Exception:
                    pass
    except Exception:
        pass

    # 3. Startup Folders
    startup_paths = []
    user_appdata = os.environ.get("APPDATA")
    if user_appdata:
        startup_paths.append((
            Path(user_appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            "User Startup Folder"
        ))

    program_data = os.environ.get("PROGRAMDATA") or "C:\\ProgramData"
    startup_paths.append((
        Path(program_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        "Common Startup Folder"
    ))

    for folder_path, loc_label in startup_paths:
        try:
            if folder_path.exists() and folder_path.is_dir():
                for entry in folder_path.iterdir():
                    if entry.name.lower() in ["desktop.ini", "thumbs.db"]:
                        continue
                    
                    is_sus, reasons = evaluate_persistence_heuristics(entry.name, loc_label, str(entry))
                    items.append(PersistenceItem(
                        name=entry.name,
                        location=str(folder_path),
                        command=str(entry),
                        file_path=str(entry),
                        type=loc_label,
                        is_suspicious=is_sus,
                        suspicious_reasons=reasons
                    ))
        except Exception:
            pass

    duration_ms = round((time.time() - t0) * 1000, 2)
    report = CollectorReport(
        collector=collector_name,
        status=status,
        item_count=len(items),
        duration_ms=duration_ms,
        error=error_msg
    )
    return items, report
