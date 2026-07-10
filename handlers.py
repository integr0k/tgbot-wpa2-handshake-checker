import asyncio
import os
import shutil
import signal
from dataclasses import dataclass
from typing import Optional, Dict

from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command, CommandStart
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, Message, ReplyKeyboardMarkup

from config import DOWNLOADS_DIR, OUTFILE_PATH, WORDLIST_PATH
from database import (
    authenticate_admin,
    clear_authorization,
    create_admin,
    ensure_default_admin,
    get_admin_by_telegram_id,
    get_admin_files,
    get_found_passwords,
    is_authorized,
    record_admin_file,
    record_found_password,
    record_current_process,
    clear_current_process,
)
import psutil

@dataclass
class ProcessState:
    process: asyncio.subprocess.Process
    pid: int
    hc22000_path: str
    admin_id: int
    chat_id: int

process_states: Dict[int, ProcessState] = {}


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


def is_pid_running(pid: int) -> bool:
    try:
        proc = psutil.Process(pid)
        return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False


def get_active_state(telegram_user_id: int) -> Optional[ProcessState]:
    state = process_states.get(telegram_user_id)
    if state and state.process.returncode is None:
        return state
    return None


async def monitor_hashcat_process(telegram_user_id: int, bot: Bot) -> None:
    state = process_states.get(telegram_user_id)
    if not state:
        return

    process = state.process
    await process.communicate()
    process_states.pop(telegram_user_id, None)
    clear_current_process(state.admin_id)

    if process.returncode == 0 and os.path.exists(OUTFILE_PATH) and os.path.getsize(OUTFILE_PATH) > 0:
        with open(OUTFILE_PATH, "r", encoding="utf-8") as f:
            result = f.read().strip()
        try:
            record_found_password(state.admin_id, result, str(OUTFILE_PATH))
        except Exception:
            pass
        await bot.send_message(
            state.chat_id,
            f"🎉 <b>SUCCESS!</b> Password found:\n<code>{result}</code>",
            parse_mode="HTML",
        )
    else:
        await bot.send_message(
            state.chat_id,
            "🔎 Hashcat finished. No password was recovered from this task.",
        )


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
        admin = get_admin_by_telegram_id(message.from_user.id)
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
        if not await require_admin(message):
            return

        existing_state = get_active_state(message.from_user.id)
        if existing_state:
            await message.answer("⚠️ Error: A cracking process is already running on your account. Stop it before starting a new one.")
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

        admin = get_admin_by_telegram_id(message.from_user.id)
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

        hashcat_proc = await asyncio.create_subprocess_exec(
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
        if not admin:
            await message.answer("⚠️ Failed to locate admin info after authentication.")
            return

        state = ProcessState(
            process=hashcat_proc,
            pid=hashcat_proc.pid,
            hc22000_path=str(hc22000_path),
            admin_id=admin["id"],
            chat_id=message.chat.id,
        )
        process_states[message.from_user.id] = state
        record_current_process(admin["id"], state.pid, state.hc22000_path)

        asyncio.create_task(monitor_hashcat_process(message.from_user.id, bot))

        await message.answer(
            text=f"🚀 Brute-force started successfully in the background!\nProcess PID: <code>{state.pid}</code>\nUse the control buttons below:",
            parse_mode="HTML",
            reply_markup=get_control_keyboard(),
        )

    @dp.callback_query(F.data.startswith("brute_"))
    async def handle_callbacks(callback: CallbackQuery):
        action = callback.data.split("_")[1]

        state = get_active_state(callback.from_user.id)
        if not state:
            await callback.answer("The cracking process is not running or has already finished!", show_alert=True)
            return

        if action == "pause":
            try:
                p = psutil.Process(state.pid)
                p.suspend()
                await callback.message.answer("Brute-force paused. The GPU is now idle.")
            except Exception:
                try:
                    os.kill(state.pid, signal.SIGSTOP)
                    await callback.message.answer("Brute-force paused. The GPU is now idle.")
                except Exception:
                    await callback.answer("Failed to pause process.", show_alert=True)
            await callback.answer()

        elif action == "resume":
            try:
                p = psutil.Process(state.pid)
                p.resume()
                await callback.message.answer("Brute-force resumed successfully on the GPU!")
            except Exception:
                try:
                    os.kill(state.pid, signal.SIGCONT)
                    await callback.message.answer("Brute-force resumed successfully on the GPU!")
                except Exception:
                    await callback.answer("Failed to resume process.", show_alert=True)
            await callback.answer()

        elif action == "stop":
            stopped = False
            try:
                p = psutil.Process(state.pid)
                p.terminate()
                p.wait(timeout=10)
                stopped = True
            except Exception:
                try:
                    os.kill(state.pid, signal.SIGTERM)
                    stopped = True
                except Exception:
                    stopped = False
            if stopped:
                process_states.pop(callback.from_user.id, None)
                clear_current_process(state.admin_id)
                await callback.message.answer("Brute-force stopped. A recovery checkpoint may have been created.")
            else:
                await callback.answer("Failed to stop process.", show_alert=True)
            await callback.answer()

        elif action == "status":
            is_running = state.process.returncode is None and is_pid_running(state.pid)
            if is_running:
                await callback.message.answer(f"📊 The process is still running (PID {state.pid}).")
            elif os.path.exists(OUTFILE_PATH) and os.path.getsize(OUTFILE_PATH) > 0:
                with open(OUTFILE_PATH, "r", encoding="utf-8") as f:
                    res = f.read().strip()
                await callback.message.answer(f"🎉 <b>PASSWORD FOUND:</b>\n<code>{res}</code>", parse_mode="HTML")
            else:
                await callback.message.answer("📊 The password has not been found yet. The process is not currently active.")
            await callback.answer()

    @dp.message(F.document)
    async def handle_wrong_document(message: Message):
        if not await require_admin(message):
            return
        await message.answer("❌ Invalid format! The bot only accepts files with the <b>.cap</b> or <b>.pcap</b> extension.", parse_mode="HTML")
