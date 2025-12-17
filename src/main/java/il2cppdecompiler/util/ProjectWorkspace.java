package il2cppdecompiler.util;

import com.google.gson.Gson;

import ghidra.program.model.listing.Function;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;

public class ProjectWorkspace {
    private final String PLUGIN_DATA_DIR_NAME = "Il2CppDecompiler";
    private final String CONFIG_FILE_NAME = "config.json";

    private final File projectRootDir;
    private Config cachedConfig;

    public ProjectWorkspace(File projectRootDir) {
        this.projectRootDir = projectRootDir;
    }

    public Config getConfig() throws IOException {
        if (cachedConfig != null)
            return cachedConfig;

        cachedConfig = readConfigFromFile();
        if (cachedConfig == null) {
            cachedConfig = new Config();
            saveConfig();
        }
        return cachedConfig;
    }

    private Config readConfigFromFile() throws IOException {
        var configFile = getProjectFile(CONFIG_FILE_NAME);
        if (!configFile.isFile())
            return null;

        try (var reader = new FileReader(configFile)) {
            return new Gson().fromJson(reader, Config.class);
        }
    }

    public void saveConfig() throws IOException {
        if (cachedConfig == null)
            return;
        saveFile(CONFIG_FILE_NAME, new Gson().toJson(cachedConfig));
    }

    public File getProjectFile(String relPath) {
        var dataDir = new File(projectRootDir, PLUGIN_DATA_DIR_NAME);
        return new File(dataDir, relPath);
    }

    public void saveFile(String relPath, String contents) throws IOException {
        var file = getProjectFile(relPath);
        file.getParentFile().mkdirs();
        try (var writer = new FileWriter(file)) {
            writer.write(contents);
        }
    }

    public String getIl2CppDumperOutputDir() throws IOException {
        return getConfig().il2CppDumperOutputDir;
    }

    public void setIl2CppDumperOutputDir(String outputDir) throws IOException {
        getConfig().il2CppDumperOutputDir = outputDir;
        saveConfig();
    }

    public File getDecompiledCsFile(Function func) {
        String safeName = func.getName().replaceAll("[/\\\\:]", "_");
        return getProjectFile("results/" + safeName + "/decompLlm.cs");
    }

    public boolean hasDecompiledCs(Function func) {
        File f = getDecompiledCsFile(func);
        return f.exists() && f.length() > 0;
    }

    public String loadDecompiledCs(Function func) throws IOException {
        return Files.readString(getDecompiledCsFile(func).toPath());
    }
}