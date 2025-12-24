package il2cppdecompiler.codeprocessing.sanitizer;

import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompileResults;

import java.util.HashMap;
import java.util.Map;

public class CodeContext {
    private final DecompileResults results;
    private final ClangTokenGroup astRoot;
    private final Map<String, Object> blackboard = new HashMap<>();

    public CodeContext(DecompileResults results) {
        this.results = results;
        this.astRoot = results != null ? results.getCCodeMarkup() : null;
    }

    public DecompileResults getResults() {
        return results;
    }

    public ClangTokenGroup getAstRoot() {
        return astRoot;
    }

    public void setMetadata(String key, Object value) {
        blackboard.put(key, value);
    }

    @SuppressWarnings("unchecked")
    public <T> T getMetadata(String key) {
        return (T) blackboard.get(key);
    }

    public String generateSourceCode() {
        return generateSourceCode(true);
    }

    public String generateSourceCode(boolean isPretty) {
        if(isPretty) return results.getDecompiledFunction().getC();
        else return astRoot.toString();
    }
}