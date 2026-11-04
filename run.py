"""Запуск CredAudit одной командой: python run.py

Поднимает сервер (сайт + проверка e-mail) на http://127.0.0.1:8000 и открывает его в браузере.
Порт можно поменять: python run.py 8080
"""
import sys
import threading
import webbrowser

HOST = "127.0.0.1"


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    try:
        import uvicorn
    except ImportError:
        sys.exit("Не установлены зависимости. Выполните: pip install -r backend/requirements.txt")
    url = f"http://localhost:{port}"
    print(f"CredAudit запущен: {url}\nЧтобы остановить, нажмите Ctrl+C в этом окне.")
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run("backend.main:app", host=HOST, port=port, log_level="warning")


if __name__ == "__main__":
    main()
