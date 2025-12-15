package il2cppdecompiler.api;

public interface Logger {
    void info(String message);

    void warn(String message);

    void error(String message);
}