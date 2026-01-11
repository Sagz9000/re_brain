/*
 * Rename a function in the current program.
 *
 * @category AI
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class RenameFunction extends GhidraScript {

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    @Override
    @SuppressWarnings({"deprecation", "removal"})
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        
        if (args.length < 2) {
            printError("Missing arguments. Usage: RenameFunction <oldName|address> <newName>");
            return;
        }

        String target = args[0];
        String newName = args[1];
        boolean found = false;
        String oldName = target;
        
        // Start transaction
        int tx = currentProgram.startTransaction("Rename Function");
        try {
            // Try to find by name first
            for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
                if (func.getName().equals(target)) {
                    func.setName(newName, SourceType.USER_DEFINED);
                    found = true;
                    break;
                }
            }
            
            // If not found by name, try address
            if (!found) {
                try {
                    ghidra.program.model.address.Address addr = currentProgram.getAddressFactory().getAddress(target);
                    Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
                    if (func != null) {
                       oldName = func.getName();
                       func.setName(newName, SourceType.USER_DEFINED);
                       found = true;
                    }
                } catch (Exception e) {
                    // Not an address
                }
            }

            if (found) {
                System.out.println("JSON_START");
                System.out.printf("{\"status\": \"success\", \"old_name\": \"%s\", \"new_name\": \"%s\"}", escape(oldName), escape(newName));
                System.out.println("\nJSON_END");

            } else {
                 printError("Function not found: " + target);
            }

        } catch (DuplicateNameException e) {
            printError("Duplicate name: " + newName);
        } catch (InvalidInputException e) {
             printError("Invalid name: " + newName);
        } catch (Exception e) {
             printError("Error renaming: " + e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, found); // Commit if found, otherwise rollback
        }
    }

    private void printError(String msg) {
        System.out.println("JSON_START");
        System.out.printf("{\"error\": \"%s\"}", escape(msg));
        System.out.println("\nJSON_END");
    }
}
