/*
 * Get cross-references (XRefs) for a specific address in the current program.
 *
 * @category AI
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.ArrayList;
import java.util.List;

public class GetXRefs extends GhidraScript {

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    @Override
    @SuppressWarnings({"deprecation", "removal"})
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        
        if (args.length < 1) {
            printError("Missing address argument.");
            return;
        }

        String addressStr = args[0];
        Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
        if (addr == null) {
            printError("Invalid address: " + addressStr);
            return;
        }

        // XRefs To
        List<String> toList = new ArrayList<>();
        ReferenceIterator toIter = currentProgram.getReferenceManager().getReferencesTo(addr);
        while (toIter.hasNext()) {
            Reference ref = toIter.next();
            toList.add(String.format("{\"from\": \"%s\", \"type\": \"%s\"}", 
                escape(ref.getFromAddress().toString()), escape(ref.getReferenceType().getName())));
        }

        // XRefs From
        List<String> fromList = new ArrayList<>();
        Reference[] fromRefs = currentProgram.getReferenceManager().getReferencesFrom(addr);
        for (Reference ref : fromRefs) {
            fromList.add(String.format("{\"to\": \"%s\", \"type\": \"%s\"}", 
                escape(ref.getToAddress().toString()), escape(ref.getReferenceType().getName())));
        }

        System.out.println("JSON_START");
        System.out.printf("{\"status\": \"success\", \"address\": \"%s\", \"xrefs_to\": [%s], \"xrefs_from\": [%s]}", 
            escape(addressStr), String.join(",", toList), String.join(",", fromList));
        System.out.println("\nJSON_END");
    }

    private void printError(String msg) {
        System.out.println("JSON_START");
        System.out.printf("{\"error\": \"%s\"}", escape(msg));
        System.out.println("\nJSON_END");
    }
}
