package il2cppdecompiler.codeprocessing.sanitizer;

public interface ICodeProcessor {
    /**
     * Основной метод обработки.
     * Процессор должен модифицировать AST внутри context.getAstRoot().
     */
    void process(CodeContext context);

    /**
     * Приоритет выполнения.
     * 0 - запускается первым (например, очистка).
     * 100 - основные трансформации.
     * 1000 - финальное форматирование.
     */
    int getPriority();
}