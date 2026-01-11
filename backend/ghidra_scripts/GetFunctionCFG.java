import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.address.Address;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

public class GetFunctionCFG extends GhidraScript {

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    @Override
    @SuppressWarnings({"deprecation", "removal"})
    public void run() throws Exception {
        // Argument: Function Address
        String[] args = getScriptArgs();
        if (args.length == 0) {
            System.out.println("JSON_START");
            System.out.println("{\"error\": \"No address provided\"}");
            System.out.println("JSON_END");
            return;
        }

        Address funcAddr = currentProgram.getAddressFactory().getAddress(args[0]);
        Function func = currentProgram.getFunctionManager().getFunctionAt(funcAddr);

        if (func == null) {
             // Try to find containing function if exact match fails
             func = currentProgram.getFunctionManager().getFunctionContaining(funcAddr);
        }

        StringBuilder json = new StringBuilder();
        json.append("{");

        if (func == null) {
            json.append("\"error\": \"Function not found at or containing " + args[0] + "\"");
        } else {
            BasicBlockModel model = new BasicBlockModel(currentProgram);
            CodeBlockIterator blocks = model.getCodeBlocksContaining(func.getBody(), monitor);

            // Store blocks to avoid duplicates and easy lookup
            List<String> blockObjs = new ArrayList<>();
            List<String> edgeObjs = new ArrayList<>();
            
            // For mapping block start address to ID/Label
            Map<String, String> blockMap = new HashMap<>();

            while (blocks.hasNext()) {
                CodeBlock block = blocks.next();
                String startAddr = block.getFirstStartAddress().toString();
                String endAddr = block.getMaxAddress().toString(); 
                
                // Get instructions
                List<String> instrs = new ArrayList<>();
                ghidra.program.model.listing.InstructionIterator ii = currentProgram.getListing().getInstructions(block, true);
                while(ii.hasNext()) {
                    Instruction inst = ii.next();
                    instrs.add(String.format("\"%s %s\"", escape(inst.getMnemonicString()), escape(inst.toString())));
                }
                
                String label = "loc_" + startAddr;
                blockMap.put(startAddr, label);

                blockObjs.add(String.format("{\"id\": \"%s\", \"start\": \"%s\", \"end\": \"%s\", \"instructions\": [%s]}", 
                    label, startAddr, endAddr, String.join(",", instrs)));

                // Edges
                CodeBlockReferenceIterator dests = block.getDestinations(monitor);
                while (dests.hasNext()) {
                    CodeBlockReference ref = dests.next();
                    String toAddr = ref.getDestinationBlock().getFirstStartAddress().toString();
                    String type = ref.getFlowType().toString();
                    // We might not have the ID for 'to' yet, but we can use loc_ convention
                    edgeObjs.add(String.format("{\"from\": \"%s\", \"to\": \"loc_%s\", \"type\": \"%s\"}", label, toAddr, type));
                }
            }

            json.append("\"name\": \"" + escape(func.getName()) + "\",");
            json.append("\"entry\": \"" + func.getEntryPoint().toString() + "\",");
            json.append("\"blocks\": [" + String.join(",", blockObjs) + "],");
            json.append("\"edges\": [" + String.join(",", edgeObjs) + "]");
        }

        json.append("}");

        System.out.println("JSON_START");
        System.out.println(json.toString());
        System.out.println("JSON_END");

    }
}
