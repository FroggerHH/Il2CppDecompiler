package il2cppdecompiler.codeprocessing.sanitizer;

import ghidra.app.decompiler.DecompileResults;

public class CodeSanitizer {
    private final ProcessorFactory processorFactory;

    public CodeSanitizer(ProcessorFactory processorFactory) {
        this.processorFactory = processorFactory;
    }

    public String processCCode(DecompileResults results) {
        CodeContext context = new CodeContext(results);
        SanitizerPipeline pipeline = new SanitizerPipeline();

        // Register processors
        pipeline.addProcessor(processorFactory.createProcessor("CommentRemover"));
        pipeline.addProcessor(processorFactory.createProcessor("FuncCallArgsUnwrapper"));
        // pipeline.addProcessor(new GhidraBoilerplateRemover());
        // pipeline.addProcessor(new VariableInliner());

        return pipeline.execute(context).generateSourceCode(true);
    }
}
