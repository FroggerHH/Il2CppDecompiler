package il2cppdecompiler.util;

public interface Logger {
    void info(String message);

    void warn(String message);

    void error(String message);

    void error(Exception exception, String message);
}