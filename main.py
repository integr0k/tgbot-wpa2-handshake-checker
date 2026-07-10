import asyncio

from aiogram import Bot, Dispatcher

from config import BOT_TOKEN
from database import init_db
from handlers import register_handlers


async def main() -> None:
    if not BOT_TOKEN:
        raise RuntimeError("Error: BOT_TOKEN was not found in the .env file!")

    init_db()

    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()
    register_handlers(dp, bot)

    print("Bot started...")
    await dp.start_polling(
        bot,
        timeout=10,
        reset_webhook=True,
    )


if __name__ == "__main__":
    asyncio.run(main())