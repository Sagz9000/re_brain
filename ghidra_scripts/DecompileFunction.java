// Decompile a function at a specific address and print to stdout
// @author
// @category Analysis
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileFunction extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("Usage: DecompileFunction <address>");
            return;
        }

        String addressStr = args[0];
        Address address = currentProgram.getAddressFactory().getAddress(addressStr);
        Function function = getFunctionAt(address);

        if (function == null) {
            // Try entry point if not at head
            function = getFunctionContaining(address);
        }

        if (function == null) {
            println("No function found at " + addressStr);
            return;
        }

        DecompInterface iface = new DecompInterface();
        iface.openProgram(currentProgram);

        DecompileResults results = iface.decompileFunction(function, 60, monitor);
        if (results.decompileCompleted()) {
            println(results.getDecompiledFunction().getC());
        } else {
            println("Decompilation failed: " + results.getErrorMessage());
        }
        
        iface.dispose();
    }
}
