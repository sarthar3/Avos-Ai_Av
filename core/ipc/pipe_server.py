"""
AVOS AI - Named Pipe IPC Server
Receives binary events from Ring 0 kernel drivers and dispatches to CSO
"""

import asyncio
import json
import logging
import struct
from typing import Callable, Optional

logger = logging.getLogger('AVOS.IPC.PipeServer')

PIPE_NAME = r'\\.\pipe\AvosCSO'
PAYMENT_PIPE_NAME = r'\\.\pipe\AvosPaymentAlert'
BUFFER_SIZE = 4096

# IPC event type codes (must match drivers)
EVENT_TYPE_MAP = {
    1: 'file_create',
    2: 'file_write',
    3: 'file_delete',
    4: 'file_execute',
    10: 'net_connect',
    11: 'net_block',
    20: 'payment_threat',
    30: 'memory_alert',
}

# Binary struct layout for IPC_FILE_EVENT (from minifilter_driver.cpp):
#   ULONG EventType (4)
#   ULONG ProcessId (4)
#   WCHAR FilePath[1024] (2048)
#   ULONG FileSize (4)
#   UCHAR Reserved[32] (32)
# Total: 2092 bytes
FILE_EVENT_STRUCT_FMT  = '<II2048sI32s'
FILE_EVENT_STRUCT_SIZE = struct.calcsize(FILE_EVENT_STRUCT_FMT)

# Binary struct layout for NET_EVENT (from wfp_driver.cpp):
#   ULONG EventType (4)
#   ULONG ProcessId (4)
#   UINT32 LocalAddr (4)
#   UINT32 RemoteAddr (4)
#   UINT16 RemotePort (2)
#   UINT8  Protocol (1)
#   WCHAR  AppPath[512] (1024)
# Total: 1043 bytes
NET_EVENT_STRUCT_FMT  = '<IIIIHHB1024s'
NET_EVENT_STRUCT_SIZE = struct.calcsize(NET_EVENT_STRUCT_FMT)


class PipeServer:
    """Async Named Pipe server for receiving driver events."""

    def __init__(self, event_callback: Callable):
        self.event_callback = event_callback
        self.running = False
        self._file_pipe_server  = None
        self._payment_pipe_server = None

    async def start(self):
        self.running = True
        logger.info(f"Starting IPC Pipe Server on {PIPE_NAME}")

        # Run both pipe servers concurrently
        await asyncio.gather(
            self._run_file_pipe_server(),
            self._run_payment_pipe_server(),
            return_exceptions=True
        )

    async def _run_file_pipe_server(self):
        """Handle file/network events from Minifilter + WFP drivers."""
        while self.running:
            try:
                import win32pipe, win32file, win32con, pywintypes
                pipe = win32pipe.CreateNamedPipe(
                    PIPE_NAME,
                    win32pipe.PIPE_ACCESS_INBOUND,
                    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    BUFFER_SIZE, BUFFER_SIZE,
                    0, None
                )

                logger.debug("Waiting for driver connection on pipe...")
                win32pipe.ConnectNamedPipe(pipe, None)

                # Handle this connection in background
                asyncio.create_task(self._handle_pipe_client(pipe))

            except Exception as e:
                logger.error(f"Pipe server error: {e}")
                await asyncio.sleep(2)

    async def _run_payment_pipe_server(self):
        """Handle payment shield alert events from payment_hook.dll."""
        while self.running:
            try:
                import win32pipe, win32file
                pipe = win32pipe.CreateNamedPipe(
                    PAYMENT_PIPE_NAME,
                    win32pipe.PIPE_ACCESS_INBOUND,
                    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    BUFFER_SIZE, BUFFER_SIZE,
                    0, None
                )
                win32pipe.ConnectNamedPipe(pipe, None)
                asyncio.create_task(self._handle_payment_pipe(pipe))

            except Exception as e:
                logger.error(f"Payment pipe server error: {e}")
                await asyncio.sleep(2)

    async def _handle_pipe_client(self, pipe):
        """Read and dispatch binary events from a connected driver pipe."""
        try:
            import win32file, pywintypes
            buffer = b''

            while True:
                try:
                    ret, data = win32file.ReadFile(pipe, BUFFER_SIZE)
                    if not data:
                        break
                    buffer += data

                    # Try to parse file events
                    while len(buffer) >= FILE_EVENT_STRUCT_SIZE:
                        chunk = buffer[:FILE_EVENT_STRUCT_SIZE]
                        buffer = buffer[FILE_EVENT_STRUCT_SIZE:]
                        event = self._parse_file_event(chunk)
                        if event:
                            await self.event_callback(event)

                except pywintypes.error:
                    break

        except Exception as e:
            logger.error(f"Pipe client handler error: {e}")
        finally:
            try:
                import win32file
                win32file.CloseHandle(pipe)
            except Exception:
                pass

    async def _handle_payment_pipe(self, pipe):
        """Read JSON messages from payment_hook.dll."""
        try:
            import win32file, pywintypes
            while True:
                try:
                    ret, data = win32file.ReadFile(pipe, BUFFER_SIZE)
                    if not data:
                        break
                    text = data.decode('utf-8', errors='replace').strip()
                    event = json.loads(text)
                    event['event_type'] = 'payment_threat'
                    await self.event_callback(event)
                except pywintypes.error:
                    break
        except Exception as e:
            logger.error(f"Payment pipe handler error: {e}")
        finally:
            try:
                import win32file
                win32file.CloseHandle(pipe)
            except Exception:
                pass

    def _parse_file_event(self, data: bytes) -> Optional[dict]:
        """Parse binary IPC_FILE_EVENT struct from minifilter driver."""
        try:
            event_type, pid, raw_path, file_size, _ = struct.unpack(FILE_EVENT_STRUCT_FMT, data)
            # Decode UTF-16 path
            path = raw_path.decode('utf-16-le', errors='replace').rstrip('\x00')
            return {
                'event_type': EVENT_TYPE_MAP.get(event_type, f'unknown_{event_type}'),
                'pid': pid,
                'path': path,
                'metadata': {'file_size': file_size}
            }
        except struct.error as e:
            logger.warning(f"Failed to parse file event struct: {e}")
            return None

    def _parse_net_event(self, data: bytes) -> Optional[dict]:
        """Parse binary NET_EVENT struct from WFP driver."""
        try:
            if len(data) < NET_EVENT_STRUCT_SIZE:
                return None
            event_type, pid, local_addr, remote_addr, local_port, remote_port, proto, raw_path = \
                struct.unpack(NET_EVENT_STRUCT_FMT, data[:NET_EVENT_STRUCT_SIZE])
            app_path = raw_path.decode('utf-16-le', errors='replace').rstrip('\x00')
            return {
                'event_type': EVENT_TYPE_MAP.get(event_type, 'net_connect'),
                'pid': pid,
                'local_addr': self._int_to_ip(local_addr),
                'remote_addr': self._int_to_ip(remote_addr),
                'remote_port': remote_port,
                'protocol': proto,
                'app_path': app_path
            }
        except struct.error as e:
            logger.warning(f"Failed to parse net event struct: {e}")
            return None

    @staticmethod
    def _int_to_ip(n: int) -> str:
        return f"{n & 0xFF}.{(n >> 8) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 24) & 0xFF}"

    async def stop(self):
        self.running = False
