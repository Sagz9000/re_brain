import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Category;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.List;

public class GetDataTypes extends GhidraScript {

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private void processCategory(Category cat, StringBuilder json) {
        json.append(String.format("{\"name\": \"%s\", \"types\": [", escape(cat.getName())));
        
        // Add Types
        DataType[] types = cat.getDataTypes();
        for (int i = 0; i < types.length; i++) {
            DataType dt = types[i];
            json.append(String.format("{\"name\": \"%s\", \"size\": %d}", escape(dt.getName()), dt.getLength()));
            if (i < types.length - 1) json.append(",");
        }
        json.append("], \"subcategories\": [");
        
        // Add Subcategories
        Category[] subcats = cat.getCategories();
        for (int i = 0; i < subcats.length; i++) {
            processCategory(subcats[i], json);
            if (i < subcats.length - 1) json.append(",");
        }
        json.append("]}");
    }

    @Override
    public void run() throws Exception {
        System.out.println("JSON_START");
        System.out.println(json.toString());
        System.out.println("JSON_END");

    }
}
