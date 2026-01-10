import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.List;

public class GetBookmarks extends GhidraScript {

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    @Override
    public void run() throws Exception {
        StringBuilder json = new StringBuilder();
        json.append("[");
        
        BookmarkManager bm = currentProgram.getBookmarkManager();
        Iterator<Bookmark> bookmarks = bm.getBookmarksIterator();
        int count = 0;
        List<String> bmkObjs = new ArrayList<>();
        
        while (bookmarks.hasNext() && count < 200) {
            Bookmark b = bookmarks.next();
            bmkObjs.add(String.format("{\"address\": \"%s\", \"type\": \"%s\", \"category\": \"%s\", \"comment\": \"%s\"}",
                b.getAddress().toString(), escape(b.getTypeString()), escape(b.getCategory()), escape(b.getComment())));
            count++;
        }
        
        json.append(String.join(",", bmkObjs));
        json.append("]");

        println("GetBookmarks.java>START");
        println(json.toString());
        println("GetBookmarks.java>END");
    }
}
