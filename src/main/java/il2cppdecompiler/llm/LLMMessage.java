package il2cppdecompiler.llm;

public class LLMMessage {
    public final String role;
    public final String content;

    public LLMMessage(String role, String content) {
        this.role = role;
        this.content = content;
    }
}