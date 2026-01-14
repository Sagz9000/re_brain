from qiling import Qiling
from qiling.const import QL_VERBOSE
import threading
import logging
import os

logger = logging.getLogger(__name__)

class QilingSession:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        # Qiling requires a rootfs. For Windows, it needs DLLs. 
        # Ideally we mount a Windows rootfs, but for simple crackmes, dynamic loading might work or we use a minimal fake root.
        # Qiling provides 'examples/rootfs/x86_windows' structure usually.
        # We might need to assume a basic setup exists or Qiling falls back.
        # For this environment, we'll point rootfs to the file's dir or a generic one.
        # NOTE: This is a best-effort minimalist emulation without a full Windows drive.
        rootfs = "/tmp/fake_windows_root"
        os.makedirs(os.path.join(rootfs, "Windows", "System32"), exist_ok=True)
        os.makedirs(os.path.join(rootfs, "Windows", "registry"), exist_ok=True)
        
        # Detect arch (assuming x86 or x64 PE)
        # We'll just let Qiling detect from binary
        
        self.ql = Qiling([binary_path], rootfs, verbose=QL_VERBOSE.DEFAULT)
        # Redirect stdout/stderr? 
        
        self.active = True
        self.lock = threading.Lock()
        
    def start(self):
        # We don't "run" the whole thing. We just prepare.
        # Or maybe we run until entry point?
        # Qiling init already sets PC to entry.
        return [{"type": "console", "payload": f"Emulation initialized for {self.binary_path}"}]

    def stop(self):
        self.active = False
        del self.ql 
        # Qiling doesn't have explicit shutdown other than cleanup

    def step_into(self):
        with self.lock:
            try:
                # emu_start is the low level API.
                # begin=PC, end=0 (means unlimited?), count=1
                # We need to get current PC
                arch_type = self.ql.arch.type # QL_ARCH.X86 or X8664
                
                # Check arch to know register name for PC? 
                # Qiling abstracts this somewhat.
                
                # Run 1 instruction
                self.ql.emu_start(self.ql.arch.regs.arch_pc, 0, count=1)
                
                new_pc = self.ql.arch.regs.arch_pc
                return [{"type": "console", "payload": f"Stepped to {hex(new_pc)}"}]
            except Exception as e:
                return [{"type": "error", "payload": str(e)}]

    def step_over(self):
        # Qiling doesn't support 'step over' natively (need to analyze opcode size or next instruction).
        # We'll fallback to step_into for now.
        return self.step_into()

    def continue_exec(self):
        # This blocks! We need a thread if we want 'continue' to be interruptible.
        # But for an MVP integration, maybe we just run a bulk of instructions?
        # Or launch a thread.
        def run_thread():
             try:
                 self.ql.emu_start(self.ql.arch.regs.arch_pc, 0)
             except Exception as e:
                 logger.error(f"Emulation error: {e}")

        t = threading.Thread(target=run_thread)
        t.daemon = True
        t.start()
        return [{"type": "console", "payload": "Running..."}]

    def add_breakpoint(self, address: str):
         # Qiling hooks address
         try:
             addr_int = int(address, 16)
             def bkpt_hook(ql):
                 ql.emu_stop()
                 logger.info(f"Breakpoint hit at {hex(ql.arch.regs.arch_pc)}")
             
             self.ql.hook_address(bkpt_hook, addr_int)
             return [{"type": "console", "payload": f"Breakpoint set at {address}"}]
         except Exception as e:
             return [{"type": "error", "payload": str(e)}]

    def get_registers(self):
        regs = {}
        # Basic set for MVP
        try:
             if self.ql.arch.type == 1: # x86
                 regs['eax'] = hex(self.ql.arch.regs.eax)
                 regs['ebx'] = hex(self.ql.arch.regs.ebx)
                 regs['ecx'] = hex(self.ql.arch.regs.ecx)
                 regs['edx'] = hex(self.ql.arch.regs.edx)
                 regs['esp'] = hex(self.ql.arch.regs.esp)
                 regs['ebp'] = hex(self.ql.arch.regs.ebp)
                 regs['eip'] = hex(self.ql.arch.regs.eip)
             else: # x64 (simplified check)
                 regs['rax'] = hex(self.ql.arch.regs.rax)
                 regs['rbx'] = hex(self.ql.arch.regs.rbx)
                 regs['rcx'] = hex(self.ql.arch.regs.rcx)
                 regs['rdx'] = hex(self.ql.arch.regs.rdx)
                 regs['rsp'] = hex(self.ql.arch.regs.rsp)
                 regs['rbp'] = hex(self.ql.arch.regs.rbp)
                 regs['rip'] = hex(self.ql.arch.regs.rip)
        except:
             pass
        return regs

    def get_memory(self, address: str, length: int = 64):
        try:
            addr_int = int(address, 16)
            mem = self.ql.mem.read(addr_int, length)
            # Format as hex dump
            return mem.hex()
        except Exception as e:
            return f"Error reading memory: {e}"

    def get_stack(self, depth: int = 10):
        # Qiling doesn't have an easy "backtrace" without analyzing stack frames manually.
        return ["Stack trace not supported in emulation mode yet."]

    def raw_command(self, cmd: str):
        return [{"type": "console", "payload": "Raw commands not supported in emulation mode."}]
