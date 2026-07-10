import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DOWNLOADS_DIR = BASE_DIR / "downloads"
DB_PATH = BASE_DIR / "bot.db"
WORDLIST_PATH = os.getenv("WORDLIST_PATH", "/mnt/storage/psswrds/rockyou2024.txt")
OUTFILE_PATH = BASE_DIR / "found_password.txt"
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change_me")

DOWNLOADS_DIR.mkdir(exist_ok=True)
