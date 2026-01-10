/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Exports memory block information for the UI program tree.
//@category RE_BRAIN
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Data;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.List;

public class GetMemoryBlocks extends GhidraScript {

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    @Override
    public void run() throws Exception {
        StringBuilder json = new StringBuilder();
        json.append("{");
        
        // 1. Memory Blocks
        json.append("\"blocks\": [");
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();
        for (int i = 0; i < blocks.length; i++) {
            MemoryBlock block = blocks[i];
            String perms = "";
            if (block.isRead()) perms += "R";
            if (block.isWrite()) perms += "W";
            if (block.isExecute()) perms += "X";
            
            json.append(String.format("{\"name\": \"%s\", \"start\": \"%s\", \"end\": \"%s\", \"size\": \"%d\", \"perms\": \"%s\", \"type\": \"%s\"}",
                escape(block.getName()), block.getStart(), block.getEnd(), block.getSize(), perms, block.getType()));
            
            if (i < blocks.length - 1) json.append(",");
        }
        json.append("],");
        
        // 2. Headers
        json.append("\"headers\": [");
        Listing listing = currentProgram.getListing();
        Data data = listing.getDataAt(currentProgram.getMinAddress());
        int count = 0;
        List<String> headerObjs = new ArrayList<>();
        while (data != null && count < 20) {
            String val = data.getValue() != null ? data.getValue().toString() : "??";
            headerObjs.add(String.format("{\"address\": \"%s\", \"type\": \"%s\", \"value\": \"%s\"}",
                data.getAddress(), escape(data.getDataType().getName()), escape(val)));
            
            data = listing.getDataAfter(data.getAddress());
            count++;
        }
        json.append(String.join(",", headerObjs));
        json.append("],");

        // 3. Data Types
        json.append("\"datatypes\": [");
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        count = 0;
        List<String> typeNames = new ArrayList<>();
        while(allTypes.hasNext() && count < 200) {
             DataType dt = allTypes.next();
             typeNames.add("\"" + escape(dt.getName()) + "\"");
             count++;
        }
        json.append(String.join(",", typeNames));
        json.append("]");

        json.append("}");

        println("GetMemoryBlocks.java>START");
        println(json.toString());
        println("GetMemoryBlocks.java>END");
    }
}
