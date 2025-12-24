package il2cppdecompiler.codeprocessing.sanitizer;

import java.util.List;

public class SanitizerTestFixture {
    public String name;
    public String functionName;
    public List<String> processors;
    public String expectedFile;

    public SanitizerTestFixture() {
    }

    public SanitizerTestFixture(String name, String functionName, List<String> processors, String expectedFile) {
        this.name = name;
        this.functionName = functionName;
        this.processors = processors;
        this.expectedFile = expectedFile;
    }

    @Override
    public String toString() {
        return name;
    }
}