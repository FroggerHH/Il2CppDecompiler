package il2cppdecompiler.llm.llm_clients;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import com.openai.client.OpenAIClient;
import com.openai.client.okhttp.OpenAIOkHttpClient;
import com.openai.models.ChatModel;
import com.openai.models.chat.completions.ChatCompletion;
import com.openai.models.chat.completions.ChatCompletionCreateParams;

import il2cppdecompiler.llm.ILLMClient;
import il2cppdecompiler.llm.LLMMessage;

public class OpenAIClientImpl implements ILLMClient {

    private final OpenAIClient client;
    private final String modelName;

    public OpenAIClientImpl(OpenAIConfig config) {
        this.modelName = config.modelName();

        this.client = OpenAIOkHttpClient.builder()
                .apiKey(config.apiKey())
                .timeout(Duration.ofSeconds(30))
                .baseUrl(config.baseUrl()).build();
    }

    @Override
    public String getName() {
        return "OpenAI API (" + modelName + ")";
    }

    @Override
    public String chat(List<LLMMessage> history, String prompt) throws Exception {
        try { 
            ChatCompletionCreateParams.Builder paramsBuilder = ChatCompletionCreateParams.builder();
            paramsBuilder.model(ChatModel.of(this.modelName));

            if (history != null) {
                for (LLMMessage msg : history) {
                    addMessage(paramsBuilder, msg.role, msg.content);
                }
            }

            addMessage(paramsBuilder, "user", prompt);

            ChatCompletion completion = client.chat().completions().create(paramsBuilder.build());

            if (completion.choices().isEmpty()) {
                throw new Exception("OpenAI API returned no choices.");
            }

            Optional<String> content = completion.choices().get(0).message().content();

            return content.orElse("");

        } catch (Exception e) {
            throw new Exception("OpenAI Request Failed: " + e.getMessage(), e);
        }
    }

    private void addMessage(ChatCompletionCreateParams.Builder builder, String role, String content) {
        if (content == null || content.isEmpty()) return;

        switch (role.toLowerCase()) {
            case "system" -> builder.addSystemMessage(content);
            case "assistant" -> builder.addAssistantMessage(content);
            case "user" -> builder.addUserMessage(content); 
            default -> builder.addUserMessage(content);
        };
    }
}