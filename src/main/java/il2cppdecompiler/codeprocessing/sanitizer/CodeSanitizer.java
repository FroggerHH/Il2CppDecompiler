package il2cppdecompiler.codeprocessing.sanitizer;

import ghidra.app.decompiler.DecompileResults;

public class CodeSanitizer {
    public static String processCCode(DecompileResults results) {
        CodeContext context = new CodeContext(results);
        SanitizerPipeline pipeline = new SanitizerPipeline();

        // Register processors
        pipeline.addProcessor(ProcessorFactory.createProcessor("CommentRemover"));
        pipeline.addProcessor(ProcessorFactory.createProcessor("FuncCallArgsUnwrapper"));
        // pipeline.addProcessor(new GhidraBoilerplateRemover());
        // pipeline.addProcessor(new VariableInliner());

        return pipeline.execute(context).generateSourceCode(true);
    }
}
