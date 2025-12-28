package il2cppdecompiler.codeprocessing.sanitizer;

import java.util.HashMap;
import java.util.Map;

import il2cppdecompiler.codeprocessing.sanitizer.processors.ast.*;
import il2cppdecompiler.util.Logger;

public class ProcessorFactory {    
    private static final Map<String, Class<? extends ICodeProcessor>> PROCESSOR_REGISTRY = new HashMap<>();
    private final Logger logger;

    static {
        PROCESSOR_REGISTRY.put("CommentRemover",                    CommentRemover.class);
        PROCESSOR_REGISTRY.put("FuncCallArgsUnwrapper",             FuncCallArgsUnwrapper.class);
        PROCESSOR_REGISTRY.put("StaticConstructorCheckRemover",     StaticConstructorCheckRemover.class);
        PROCESSOR_REGISTRY.put("TypeInitializationCheckRemover",    TypeInitializationCheckRemover.class);
    }

    public ProcessorFactory(Logger logger) {
        this.logger = logger;
    }

    public ICodeProcessor createProcessor(String processorName) {
        Class<? extends ICodeProcessor> processorClass = PROCESSOR_REGISTRY.get(processorName);
        if (processorClass == null) {
            throw new IllegalArgumentException("Unknown processor: " + processorName);
        }

        try {
            return processorClass.getDeclaredConstructor(Logger.class).newInstance(logger);
        } catch (Exception e) {
            throw new RuntimeException("Failed to instantiate processor: " + processorName, e);
        }
    }
}