package il2cppdecompiler.codeprocessing.sanitizer;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class SanitizerPipeline {
    private final List<ICodeProcessor> processors = new ArrayList<>();

    public void addProcessor(ICodeProcessor processor) {
        processors.add(processor);
        processors.sort(Comparator.comparingInt(ICodeProcessor::getPriority));
    }

    public CodeContext execute(CodeContext context) {
        for (ICodeProcessor processor : processors) {
            processor.process(context);
        }

        return context;
    }
}
