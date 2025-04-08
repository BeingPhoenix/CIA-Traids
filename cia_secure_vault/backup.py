# backup.py
import os
import shutil

def backup_file(file_path: str, backup_dir: str) -> None:
    """
    Copy the file to the backup directory. If backup directory does not exist, create it.
    """
    if not os.path.isdir(backup_dir):
        os.makedirs(backup_dir)
    shutil.copy2(file_path, backup_dir)
