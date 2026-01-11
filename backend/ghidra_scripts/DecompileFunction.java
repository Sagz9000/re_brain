import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitor;

public class DecompileFunction extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            System.out.println("JSON_START");
            System.out.println("{\"error\": \"No address provided\"}");
            System.out.println("JSON_END");
            return;
        }

        Address funcAddr = currentProgram.getAddressFactory().getAddress(args[0]);
        Function func = currentProgram.getFunctionManager().getFunctionContaining(funcAddr);

        if (func == null) {
            System.out.println("JSON_START");
            System.out.println("{\"error\": \"Function not found at " + args[0] + "\"}");
            System.out.println("JSON_END");
            return;
        }

        DecompInterface decomplib = new DecompInterface();
        decomplib.openProgram(currentProgram);

        DecompileResults res = decomplib.decompileFunction(func, 60, monitor);

        System.out.println("JSON_START");
        System.out.print("{\"code\": \"");
        if (res.decompileCompleted()) {
            String cCode = res.getDecompiledFunction().getC();
            // Basic JSON escaping
            cCode = cCode.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
            System.out.print(cCode);
        } else {
            System.out.print("// Decompilation Failed: " + res.getErrorMessage());
        }
        System.out.println("\"}");
        System.out.println("JSON_END");

        
        decomplib.dispose();
    }
}
