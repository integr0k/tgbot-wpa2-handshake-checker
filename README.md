# Private Bot

A Telegram bot for managing admin access, storing uploaded handshake files, and tracking brute-force results.

## Features

- Password-based admin authentication
- SQLite storage for admins, files, and found passwords
- Brute-force control buttons for pause/resume/stop/status
- Local file handling for `.cap` and `.pcap` handshake uploads

## Requirements

- Python 3.10+
- A Telegram bot token from BotFather
- Optional: `hashcat` and `hcxpcapngtool` installed on the server for cracking workflows

## Environment variables

Create a `.env` file in the project root with the following values:

```env
BOT_TOKEN=your_bot_token_here
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change_me
WORDLIST_PATH=/mnt/storage/psswrds/rockyou2024.txt
```

You can copy the sample file:

```bash
copy .env.example .env
```

## Setup

Create and activate a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not present yet, install manually:

```bash
pip install aiogram python-dotenv
```

## Run

```bash
python main.py
```

## Commands

- `/login <password>` — authenticate as admin
- `/logout` — log out
- `/history` — view recent uploaded files and found passwords
- `/admin <username> <password>` — create a new admin account

## Notes

- The database is stored in `bot.db`
- Uploaded files are stored in the `downloads/` folder
- The bot uses SQLite locally, so no external database server is required
