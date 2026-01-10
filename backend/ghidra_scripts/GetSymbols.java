import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolIterator;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.List;

public class GetSymbols extends GhidraScript {

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    @Override
    public void run() throws Exception {
        StringBuilder json = new StringBuilder();
        json.append("{");

        // 1. Functions
        json.append("\"functions\": [");
        FunctionManager fm = currentProgram.getFunctionManager();
        Iterator<Function> functions = fm.getFunctions(true);
        int count = 0;
        List<String> funcObjs = new ArrayList<>();
        while (functions.hasNext() && count < 200) {
            Function func = functions.next();
            funcObjs.add(String.format("{\"name\": \"%s\", \"address\": \"%s\", \"size\": %d}", 
                escape(func.getName()), func.getEntryPoint().toString(), func.getBody().getNumAddresses()));
            count++;
        }
        json.append(String.join(",", funcObjs));
        json.append("],");

        // 2. Imports (External)
        json.append("\"imports\": [");
        SymbolIterator extSyms = currentProgram.getSymbolTable().getExternalSymbols();
        count = 0;
        List<String> impObjs = new ArrayList<>();
        while (extSyms.hasNext() && count < 200) {
            Symbol sym = extSyms.next();
             if (sym.getSymbolType() == SymbolType.FUNCTION || sym.getSymbolType() == SymbolType.LABEL) {
                impObjs.add(String.format("{\"name\": \"%s\", \"address\": \"%s\"}", 
                    escape(sym.getName()), sym.getAddress().toString()));
                count++;
             }
        }
        json.append(String.join(",", impObjs));
        json.append("],");

        // 3. Exports (Global symbols)
        json.append("\"exports\": [");
        SymbolIterator definedSyms = currentProgram.getSymbolTable().getAllSymbols(true);
        count = 0;
        List<String> expObjs = new ArrayList<>();
        // Simple heuristic: global symbols that are functions but not thunks
        while (definedSyms.hasNext() && count < 100) {
            Symbol sym = definedSyms.next();
            if (sym.isGlobal() && !sym.isExternal() && (sym.getSymbolType() == SymbolType.LABEL || sym.getSymbolType() == SymbolType.FUNCTION)) {
                 expObjs.add(String.format("{\"name\": \"%s\", \"address\": \"%s\"}", 
                    escape(sym.getName()), sym.getAddress().toString()));
                count++;
            }
        }
        json.append(String.join(",", expObjs));
        json.append("]");

        json.append("}");

        println("GetSymbols.java>START");
        println(json.toString());
        println("GetSymbols.java>END");
    }
}
