import threading, time
from app import create_app
from app.sync_devices import sync_devices

app = create_app()

def periodic_scan():
    while True:
        sync_devices(app)
        time.sleep(30)   # rescan every 30 seconds

if __name__ == "__main__":
    threading.Thread(target=periodic_scan, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
