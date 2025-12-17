package il2cppdecompiler.llm;

import java.util.List;

public interface ILLMClient {
    /**
     * Sends a chat prompt to the LLM.
     * @param history List of previous messages in the conversation
     * @param prompt The new user prompt
     * @return The model's response text
     * @throws Exception If communication fails or is cancelled
     */
    String chat(List<LLMMessage> history, String prompt) throws Exception;

    /** Returns the display name of this client implementation */
    String getName();
}