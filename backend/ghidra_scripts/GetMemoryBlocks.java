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

public class GetMemoryBlocks extends GhidraScript {

    @Override
    public void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();
        
        println("GetMemoryBlocks.java>START");
        for (MemoryBlock block : blocks) {
            String name = block.getName();
            String start = block.getStart().toString();
            String end = block.getEnd().toString();
            long size = block.getSize();
            String perms = "";
            if (block.isRead()) perms += "R";
            if (block.isWrite()) perms += "W";
            if (block.isExecute()) perms += "X";
            
            // Output format: Name|Start|End|Size|Perms|Type
            println(name + "|" + start + "|" + end + "|" + size + "|" + perms + "|" + block.getType().toString());
        }
        println("GetMemoryBlocks.java>END");
    }
}
