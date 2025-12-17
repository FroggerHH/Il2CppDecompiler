package il2cppdecompiler.llm.llm_clients;

public record OpenAIConfig(
    String apiKey,
    String modelName,
    String baseUrl
) {}