import logging
from pygdbmi.gdbcontroller import GdbController
import threading
import time
import os

logger = logging.getLogger(__name__)

class DebugSession:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.active = True
        self.mode = "gdb"
        self.lock = threading.RLock() # Use RLock to prevent self-deadlock
        self.initializing = False # Flag to indicate startup in progress

        # Check if PE file
        is_pe = False
        try:
            with open(binary_path, "rb") as f:
                magic = f.read(2)
                if magic == b"MZ":
                    is_pe = True
        except:
            pass
        
        # Ensure Wine doesn't pop up "Gecko/Mono installer" dialogs which block headless execution
        os.environ["WINEDLLOVERRIDES"] = "mscoree,mshtml="
        os.environ["WINEDEBUG"] = "-all"
        
        if is_pe:
            logger.info("Detected PE binary, switching to Wine Debugging")
            self.mode = "wine"
            # Launch GDB with target remote pipe to winedbg
            # We use --interpreter=mi to ensure we can talk to it via pygdbmi
            # winedbg --gdb --no-gui runs a gdb server on stdin/stdout
            # Container now has persistent Xvfb on :99. We rely on DISPLAY env var.
            command_list = [
                "gdb", 
                "--interpreter=mi", 
                "-ex", f"file \"{binary_path}\"", 
                "-ex", f"target remote | /usr/bin/winedbg --gdb --no-gui \"{binary_path}\""
            ]
            self.controller = GdbController(command=command_list)
        else:
            self.mode = "gdb"
            self.controller = GdbController()
            # Initial setup for GDB native
            self._send_command_gdb(f'-file-exec-and-symbols "{binary_path}"')
        
        # Common setup
        self._send_command_gdb("set pagination off")
        
    def _send_command_gdb(self, cmd: str, timeout: float = 10.0):
        if not self.active:
            return [{"type": "error", "payload": "Session inactive"}]
            
        with self.lock:
            try:
                logger.info(f"GDB CMD: {cmd}")
                response = self.controller.write(cmd, timeout_sec=timeout)
                return response
            except Exception as e:
                logger.error(f"GDB Error: {e}")
                return [{"type": "error", "payload": str(e)}]

    def start(self):
        # For wine, we need to do a complex startup sequence that can take time.
        # to avoid blocking the API (and causing socket hangups), we run this in a thread.
        if self.mode == "wine":
             self.initializing = True
             self.wine_startup_thread = threading.Thread(target=self._wine_startup_routine)
             self.wine_startup_thread.daemon = True
             self.wine_startup_thread.start()
             return [{"type": "console", "payload": "Wine initialization started in background..."}]
        return self._send_command_gdb("start")

    def _wine_startup_routine(self):
         logger.info("Starting Wine initialization routine...")
         try:
             # 1. Find entry point
             # No need to manually lock, _send_command_gdb handles it (and we use RLock now anyway)
             res = self._send_command_gdb("info file", timeout=30) # increased timeout for info file (Wine init is slow)
             
             logger.info(f"Info file result: {res}")
             entry_point = None
             for line in res:
                 if line['type'] == 'console':
                     txt = line['payload'].lower()
                     if "entry point" in txt:
                         parts = txt.split(":")
                         if len(parts) > 1:
                             entry_point = parts[1].strip()
                             break
             
             if entry_point:
                 logger.info(f"Setting breakpoint at entry point: {entry_point}")
                 self.add_breakpoint(entry_point)
             else:
                 logger.warning("Could not find entry point, setting fallback breakpoint at 0x401000 and 0x140001000")
                 self.add_breakpoint("0x401000") 
                 self.add_breakpoint("0x140001000") 
                 
             # Strategy: Force Interrupt
             # We assume process starts running. We wait a bit (to let loader finish), then interrupt.
             # This should land us *somewhere* in the code (ntdll or main).
             self._send_command_gdb("continue", timeout=0.5)
             
             logger.info("Waiting 6s before interrupting...")
             time.sleep(6)
             
             logger.info("Sending Interrupt to pause execution...")
             # Send interrupt (SIGINT/Ctrl+C equivalent in GDB MI)
             # Pygdbmi doesn't have a direct interrupt method easily exposed, but .write with appropriate signal works
             # Actually, for MI, we should send -exec-interrupt
             try:
                 self.controller.write("-exec-interrupt", timeout_sec=2)
             except:
                pass # it might timeout if already stopped
             
             # Now check where we are
             with self.lock:
                 self._send_command_gdb("info sharedlibrary", timeout=2)
                 pc_res = self._send_command_gdb("x/i $pc", timeout=2)
             
             logger.info(f"Interrupt PC: {pc_res}")
             
             self.initializing = False
             pass
         except Exception as e:
             logger.error(f"Error in wine startup: {e}")
         finally:
             self.initializing = False # Always clear flag

    def stop(self):
        self.active = False
        try:
            self.controller.exit()
        except:
            pass

    def step_into(self):
        return self._send_command_gdb("stepi")

    def step_over(self):
        return self._send_command_gdb("nexti")

    def continue_exec(self):
        return self._send_command_gdb("continue")

    def add_breakpoint(self, address: str):
        return self._send_command_gdb(f"break *{address}")

    def remove_breakpoint(self, address: str):
        return self._send_command_gdb(f"clear *{address}")

    def get_registers(self):
        if self.initializing:
            return {} # Return empty if initializing to avoid blocking
            
        # GDB logic...
        # -data-list-register-values x (hex)
        res = self._send_command_gdb("-data-list-register-values x")
        
        # Simpler approach: 'info registers' (console output)
        cli_res = self._send_command_gdb("info registers")
        # Parse console lines
        parsed_regs = {}
        for line in cli_res:
            if line['type'] == 'console':
                payload = line['payload']
                # rax            0x0                 0
                parts = payload.strip().split()
                if len(parts) >= 2:
                    parsed_regs[parts[0]] = parts[1]
        return parsed_regs

    def get_memory(self, address: str, length: int = 64):
        """Read memory at address"""
        # x/32bx address
        cmd = f"x/{length}bx {address}"
        res = self._send_command_gdb(cmd)
        
        mem_data = []
        for line in res:
            if line['type'] == 'console':
                # 0x0000: 00 01 02 ...
                mem_data.append(line['payload'].strip())
        return "\n".join(mem_data)

    def get_stack(self, depth: int = 10):
        if self.initializing:
            return []
            
        """Get stack trace"""
        res = self._send_command_gdb(f"bt {depth}")
        stack = []
        for line in res:
            if line['type'] == 'console':
                stack.append(line['payload'].strip())
        return stack
    
    def raw_command(self, cmd: str):
        return self._send_command_gdb(cmd)
