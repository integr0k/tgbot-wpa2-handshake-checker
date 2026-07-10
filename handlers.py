import asyncio
import os
import shutil
import signal
from typing import Optional

from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command, CommandStart
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, Message, ReplyKeyboardMarkup

from config import ADMIN_USERNAME, DOWNLOADS_DIR, OUTFILE_PATH, WORDLIST_PATH
from database import (
    authenticate_admin,
    clear_authorization,
    create_admin,
    ensure_default_admin,
    get_admin_by_username,
    get_admin_files,
    get_found_passwords,
    is_authorized,
    record_admin_file,
    record_found_password,
    record_current_process,
    get_current_process,
    clear_current_process,
)
import psutil

current_process = None
current_pid = None


def get_reply_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(keyboard=[[KeyboardButton(text="send handshake")]], resize_keyboard=True)


def get_control_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        [
            InlineKeyboardButton(text="Pause", callback_data="brute_pause"),
            InlineKeyboardButton(text="Resume", callback_data="brute_resume"),
        ],
        [
            InlineKeyboardButton(text="Status", callback_data="brute_status"),
            InlineKeyboardButton(text="Stop", callback_data="brute_stop"),
        ],
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


async def require_admin(message: Message) -> bool:
    if is_authorized(message.from_user.id):
        return True
    await message.answer("Authentication required. Use /login <password>")
    return False


def register_handlers(dp: Dispatcher, bot: Bot) -> None:
    ensure_default_admin()

    @dp.message(CommandStart())
    async def cmd_start(message: Message):
        if not is_authorized(message.from_user.id):
            await message.answer(
                "Welcome. To access the bot, enter your password: /login <password>",
                reply_markup=get_reply_keyboard(),
            )
            return
        await message.answer(
            f"Welcome, admin {ADMIN_USERNAME}!",
            reply_markup=get_reply_keyboard(),
        )

    @dp.message(Command("login"))
    async def cmd_login(message: Message):
        if is_authorized(message.from_user.id):
            await message.answer("You are already authenticated")
            return

        password = message.text.replace("/login", "", 1).strip()
        if not password:
            await message.answer("Use the format: /login <password>")
            return

        ok, reason = authenticate_admin(ADMIN_USERNAME, password, message.from_user.id)
        if ok:
            await message.answer("Authentication successful. You can now use the bot.")
        else:
            await message.answer(reason)

    @dp.message(Command("logout"))
    async def cmd_logout(message: Message):
        clear_authorization(message.from_user.id)
        await message.answer("You have logged out")

    @dp.message(Command("admin"))
    async def cmd_admin(message: Message):
        if not await require_admin(message):
            return
        parts = message.text.split()
        if len(parts) < 3:
            await message.answer("Use: /admin <username> <password>")
            return
        success, response = create_admin(parts[1], parts[2])
        await message.answer(response)

    @dp.message(Command("history"))
    async def cmd_history(message: Message):
        if not await require_admin(message):
            return
        admin = get_admin_by_username(ADMIN_USERNAME)
        if not admin:
            await message.answer("Admin not found")
            return
        files = get_admin_files(admin["id"])
        passwords = get_found_passwords(admin["id"])
        text = ["📁 Recent files:"]
        if files:
            for row in files:
                text.append(f"- {row['filename']} ({row['uploaded_at']})")
        else:
            text.append("- No uploaded files yet")

        text.append("\n🔐 Recent found passwords:")
        if passwords:
            for row in passwords:
                text.append(f"- {row['password']} | {row['source_file']} ({row['found_at']})")
        else:
            text.append("- No saved results yet")
        await message.answer("\n".join(text))

    @dp.message(F.text == "send handshake")
    async def process_hello_button(message: Message):
        if not await require_admin(message):
            return
        await message.answer(f"Send your `.cap` or `.pcap` handshake file, {message.from_user.full_name}:")

    @dp.message(F.document & F.document.file_name.lower().endswith((".cap", ".pcap")))
    async def handle_handshake_document(message: Message):
        global current_process, current_pid

        if not await require_admin(message):
            return

        if current_process and current_process.returncode is None:
            await message.answer("⚠️ Error: A cracking process is already running on the server. Stop it before starting a new one.")
            return

        if not shutil.which("hcxpcapngtool"):
            await message.answer("❌ Error: `hcxtools` is not installed on the server!")
            return
        if not shutil.which("hashcat"):
            await message.answer("❌ Error: `hashcat` is not installed on the server!")
            return

        document = message.document
        await message.answer(f"File <b>{document.file_name}</b> received! Downloading...", parse_mode="HTML")

        file_info = await bot.get_file(document.file_id)
        cap_path = os.path.join(DOWNLOADS_DIR, document.file_name)
        await bot.download_file(file_path=file_info.file_path, destination=cap_path)

        admin = get_admin_by_username(ADMIN_USERNAME)
        if admin:
            record_admin_file(admin["id"], document.file_name, document.file_id, cap_path)

        hc22000_path = cap_path + ".hc22000"
        await message.answer("🔄 Converting the handshake locally to `.hc22000` format...")

        convert_proc = await asyncio.create_subprocess_exec(
            "hcxpcapngtool",
            "-o",
            hc22000_path,
            cap_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await convert_proc.communicate()

        if not os.path.exists(hc22000_path) or os.path.getsize(hc22000_path) == 0:
            await message.answer("❌ Conversion failed! No valid Wi-Fi handshake (EAPOL) was found in your file.")
            return

        await message.answer("✅ Conversion successful! Starting the brute-force...")

        if os.path.exists(OUTFILE_PATH):
            os.remove(OUTFILE_PATH)

        current_process = await asyncio.create_subprocess_exec(
            "hashcat",
            "-m",
            "22000",
            hc22000_path,
            WORDLIST_PATH,
            "--force",
            "--self-test-disable",
            "-n",
            "16",
            "-T",
            "64",
            "--quiet",
            "--outfile",
            str(OUTFILE_PATH),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        current_pid = current_process.pid
        try:
            admin = get_admin_by_username(ADMIN_USERNAME)
            if admin:
                record_current_process(admin["id"], current_pid, str(hc22000_path))
        except Exception:
            pass

        await message.answer(
            text=f"🚀 Brute-force started successfully in the background!\nProcess PID: <code>{current_pid}</code>\nUse the control buttons below:",
            parse_mode="HTML",
            reply_markup=get_control_keyboard(),
        )

    @dp.callback_query(F.data.startswith("brute_"))
    async def handle_callbacks(callback: CallbackQuery):
        global current_process, current_pid
        action = callback.data.split("_")[1]

        admin = get_admin_by_username(ADMIN_USERNAME)
        if (not current_process or getattr(current_process, "returncode", None) is not None):
            current_pid_db = None
            if admin:
                row = get_current_process(admin["id"])
                if row:
                    current_pid_db = row["pid"]
            if current_pid_db:
                current_pid = current_pid_db
            else:
                await callback.answer("The cracking process is not running or has already finished!", show_alert=True)
                return

        if action == "pause":
            try:
                p = psutil.Process(current_pid)
                p.suspend()
                await callback.message.answer("Brute-force paused. The GPU is now idle.")
            except Exception:
                try:
                    os.kill(current_pid, signal.SIGSTOP)
                    await callback.message.answer("Brute-force paused. The GPU is now idle.")
                except Exception:
                    await callback.answer("Failed to pause process.", show_alert=True)
            await callback.answer()

        elif action == "resume":
            try:
                p = psutil.Process(current_pid)
                p.resume()
                await callback.message.answer("Brute-force resumed successfully on the GPU!")
            except Exception:
                try:
                    os.kill(current_pid, signal.SIGCONT)
                    await callback.message.answer("Brute-force resumed successfully on the GPU!")
                except Exception:
                    await callback.answer("Failed to resume process.", show_alert=True)
            await callback.answer()

        elif action == "stop":
            stopped = False
            try:
                p = psutil.Process(current_pid)
                p.terminate()
                p.wait(timeout=10)
                stopped = True
            except Exception:
                try:
                    os.kill(current_pid, signal.SIGTERM)
                    stopped = True
                except Exception:
                    stopped = False
            try:
                if admin:
                    clear_current_process(admin["id"])
            except Exception:
                pass
            if stopped:
                await callback.message.answer("Brute-force stopped. A recovery checkpoint may have been created.")
            else:
                await callback.answer("Failed to stop process.", show_alert=True)
            await callback.answer()

        elif action == "status":
            if os.path.exists(OUTFILE_PATH) and os.path.getsize(OUTFILE_PATH) > 0:
                with open(OUTFILE_PATH, "r", encoding="utf-8") as f:
                    res = f.read().strip()
                admin = get_admin_by_username(ADMIN_USERNAME)
                if admin:
                    record_found_password(admin["id"], res, str(OUTFILE_PATH))
                await callback.message.answer(f"🎉 <b>BINGO! PASSWORD FOUND:</b>\n<code>{res}</code>", parse_mode="HTML")
            else:
                await callback.message.answer("📊 The password has not been found yet. Brute-force is still running in the background.")
            await callback.answer()

    @dp.message(F.document)
    async def handle_wrong_document(message: Message):
        if not await require_admin(message):
            return
        await message.answer("❌ Invalid format! The bot only accepts files with the <b>.cap</b> or <b>.pcap</b> extension.", parse_mode="HTML")
