package il2cppdecompiler.codeprocessing.sanitizer;

import com.google.gson.Gson;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class SanitizerTestConfig {
    public List<SanitizerTestFixture> tests;

    public static SanitizerTestConfig loadFromJsonFile(Path configPath) throws IOException {
        String json = Files.readString(configPath);
        Gson gson = new Gson();
        return gson.fromJson(json, SanitizerTestConfig.class);
    }
}