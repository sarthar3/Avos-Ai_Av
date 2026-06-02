import os
import logging
import asyncio
from pathlib import Path

logger = logging.getLogger('AVOS.DOWNLOADS')


class DownloadsMonitor:
    """Monitors the Windows Downloads folder for new files."""

    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.downloads_path = str(Path.home() / "Downloads")
        self._observer = None

    async def start(self):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            logger.warning(
                "watchdog package not installed — Downloads monitor disabled. "
                "Run: pip install watchdog"
            )
            return

        if not os.path.exists(self.downloads_path):
            logger.warning(f"Downloads folder not found: {self.downloads_path}")
            return

        loop = asyncio.get_running_loop()
        orchestrator = self.orchestrator

        class _NewFileHandler(FileSystemEventHandler):
            def on_created(self, event):
                if event.is_directory:
                    return
                path = event.src_path
                if path.endswith(('.tmp', '.crdownload', '.partial')):
                    return
                logger.info(f"New download detected: {path}")
                asyncio.run_coroutine_threadsafe(
                    orchestrator.publish('file.scan', {
                        'path': path, 'source': 'downloads_monitor'
                    }),
                    loop
                )

        self._observer = Observer()
        self._observer.schedule(_NewFileHandler(), self.downloads_path, recursive=False)
        self._observer.start()
        logger.info(f"Downloads monitor started for: {self.downloads_path}")

        # Keep running until stopped
        try:
            while self._observer and self._observer.is_alive():
                await asyncio.sleep(5)
        except asyncio.CancelledError:
            pass

    async def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()
            self._observer = None
            logger.info("Downloads monitor stopped.")
