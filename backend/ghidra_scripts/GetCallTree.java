import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.List;

public class GetCallTree extends GhidraScript {

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private String getFuncJson(Function f) {
         if (f == null) return "null";
         return String.format("{\"name\": \"%s\", \"address\": \"%s\"}", escape(f.getName()), f.getEntryPoint().toString());
    }

    @Override
    public void run() throws Exception {
        StringBuilder json = new StringBuilder();
        json.append("{");
        
        // Use current location or finding main/entry
        Function func = getFunctionContaining(currentAddress);
        if (func == null) {
             FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
             if (fi.hasNext()) func = fi.next();
        }

        if (func != null) {
            json.append(String.format("\"current\": %s,", getFuncJson(func)));
            
            // Callers (Incoming)
            json.append("\"callers\": [");
            Set<Function> callers = new HashSet<>();
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint());
            List<String> callerJson = new ArrayList<>();
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null && !callers.contains(caller)) {
                    callers.add(caller);
                    callerJson.add(getFuncJson(caller));
                }
            }
            json.append(String.join(",", callerJson));
            json.append("],");

            // Callees (Outgoing)
            json.append("\"callees\": [");
            Set<Function> callees = func.getCalledFunctions(monitor);
            List<String> calleeJson = new ArrayList<>();
            for (Function callee : callees) {
                 calleeJson.add(getFuncJson(callee));
            }
            json.append(String.join(",", calleeJson));
            json.append("]");

        } else {
             json.append("\"current\": null, \"callers\": [], \"callees\": []");
        }
        
        json.append("}");

        println("GetCallTree.java>START");
        println(json.toString());
        println("GetCallTree.java>END");
    }
}
