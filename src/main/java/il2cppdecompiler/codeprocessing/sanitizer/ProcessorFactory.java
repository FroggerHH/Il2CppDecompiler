package il2cppdecompiler.codeprocessing.sanitizer;

import java.util.HashMap;
import java.util.Map;

import il2cppdecompiler.codeprocessing.sanitizer.processors.ast.*;

public class ProcessorFactory {
    private static final Map<String, Class<? extends ICodeProcessor>> PROCESSOR_REGISTRY = new HashMap<>();

    static {
        PROCESSOR_REGISTRY.put("CommentRemover", CommentRemover.class);
        PROCESSOR_REGISTRY.put("FuncCallArgsUnwrapper", FuncCallArgsUnwrapper.class);
    }

    public static ICodeProcessor createProcessor(String processorName) {
        Class<? extends ICodeProcessor> processorClass = PROCESSOR_REGISTRY.get(processorName);
        if (processorClass == null) {
            throw new IllegalArgumentException("Unknown processor: " + processorName);
        }

        try {
            return processorClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Failed to instantiate processor: " + processorName, e);
        }
    }

    public static void registerProcessor(String name, Class<? extends ICodeProcessor> processorClass) {
        PROCESSOR_REGISTRY.put(name, processorClass);
    }
}