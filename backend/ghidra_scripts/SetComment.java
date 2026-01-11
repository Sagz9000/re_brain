/*
 * Set a comment at a specific address in the current program.
 *
 * @category AI
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class SetComment extends GhidraScript {

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    @Override
    @SuppressWarnings({"deprecation", "removal"})
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        
        if (args.length < 2) {
            printError("Missing arguments. Usage: SetComment <address> <comment> [type]");
            return;
        }

        String addressStr = args[0];
        String comment = args[1];
        String type = (args.length > 2) ? args[2].toLowerCase() : "plate";

        Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
        if (addr == null) {
            printError("Invalid address: " + addressStr);
            return;
        }

        int tx = currentProgram.startTransaction("Set Comment");
        boolean success = false;
        try {
            // Using raw constants to avoid CodeUnit import issues
            // EOL=0, PRE=1, POST=2, PLATE=3
            int commentType = 3; // PLATE
            if (type.equals("plate")) {
                commentType = 3;
            } else if (type.equals("pre")) {
                commentType = 1;
            } else if (type.equals("post")) {
                commentType = 2;
            } else if (type.equals("eol")) {
                commentType = 0;
            } else {
                printError("Invalid comment type: " + type);
                return;
            }
            
            currentProgram.getListing().setComment(addr, commentType, comment);
            success = true;
            
            System.out.println("JSON_START");
            System.out.printf("{\"status\": \"success\", \"address\": \"%s\", \"type\": \"%s\"}", escape(addressStr), escape(type));
            System.out.println("\nJSON_END");
        } catch (Exception e) {
            printError("Error setting comment: " + e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, success);
        }
    }

    private void printError(String msg) {
        System.out.println("JSON_START");
        System.out.printf("{\"error\": \"%s\"}", escape(msg));
        System.out.println("\nJSON_END");
    }
}
