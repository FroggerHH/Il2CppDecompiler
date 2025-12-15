package il2cppdecompiler.plugin;

import ghidra.app.CorePluginPackage;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

import il2cppdecompiler.api.LLMClient;
import il2cppdecompiler.api.Logger;
import il2cppdecompiler.impl.ManualLLMClient;
import il2cppdecompiler.model.DecompiledType;
import il2cppdecompiler.model.LLMMessage;
import il2cppdecompiler.service.CodeSanitizer;
import il2cppdecompiler.service.DumperParser;
import il2cppdecompiler.service.ProjectWorkspace;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "LLM C# Decompiler",
    description = "Decompiles IL2CPP functions to C# using LLM"
)
//@formatter:on
public class Il2CppDecompilerPlugin extends ProgramPlugin {

    private Il2CppDecompilerProvider provider;

    private volatile boolean isReady = false;

    // Services
    private ProjectWorkspace workspace;
    private CodeSanitizer sanitizer;
    private DumperParser dumper;
    private LLMClient llmClient;
    private Logger logger;

    public Il2CppDecompilerPlugin(PluginTool tool) {
        super(tool);
        provider = new Il2CppDecompilerProvider(this, "Il2Cpp");
    }

    @Override
    protected void init() {
        super.init();
        logger = createLogger();
        createMenuAction();
    }

    private void createMenuAction() {
        DockingAction action = new DockingAction("Show Il2Cpp Viewer", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                provider.setVisible(true);
            }
        };
        action.setMenuBarData(new MenuData(
            new String[] { "Tools", "Il2Cpp", "Show C# Viewer" },
            null,
            "Il2Cpp"));
        getTool().addAction(action);
    }

    @Override
    public void dispose() {
        if (provider != null) {
            provider.closeComponent();
            provider = null;
        }
        super.dispose();
    }

    @Override
    public void programActivated(Program program) {
        super.programActivated(program);
        provider.setVisible(true);
        isReady = false;

        try {
            File projectDir = program.getDomainFile().getParent().getProjectLocator().getProjectDir();
            workspace = new ProjectWorkspace(projectDir);
            sanitizer = new CodeSanitizer();
            llmClient = new ManualLLMClient();

            String dumperPath = workspace.getIl2CppDumperOutputDir();
            if (dumperPath != null) {
                dumper = new DumperParser(workspace, dumperPath, logger);
                SwingUtilities.invokeLater(() -> provider.setLoadingState("Parsing Il2Cpp dump..."));
                new Thread(() -> {
                    try {
                        logger.info("Starting to parse Il2CppDumper output from: " + dumperPath);
                        dumper.parse();
                        isReady = true;
                        logger.info("Il2CppDumper output parsed successfully");
                        
                        SwingUtilities.invokeLater(() -> {locationChanged(currentLocation);});
                    }
                    catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();
            } else {
                SwingUtilities.invokeLater(() -> provider.setLoadingState("Il2Cpp dump not found. Please configure the dumper path."));
                logger.warn("Il2Cpp dumper output directory not configured");
                isReady = true;
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void locationChanged(ProgramLocation loc) {
        if (provider == null || !provider.isVisible())
            return;

        Function func = null;
        if (loc != null) {
            func = loc.getProgram().getFunctionManager().getFunctionContaining(loc.getAddress());
        }

        if (workspace != null) {
            provider.updateLocation(func, workspace, isReady);
        }
    }

    public ProjectWorkspace getWorkspace() {
        return workspace;
    }

    // --- Логика декомпиляции (перенесена из скрипта) ---

    public void decompileFunction(Function func, Runnable onComplete) {
        Task task = new Task("LLM Decompilation", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    doDecompile(func, monitor);
                }
                catch (Exception e) {
                    // Ghidra way to show error
                    ghidra.util.Msg.showError(this, null, "Decompilation Error", e.getMessage(), e);
                }
                finally {
                    onComplete.run();
                }
            }
        };
        new TaskLauncher(task, provider.getComponent());
    }

    private void doDecompile(Function func, TaskMonitor monitor) throws Exception {
        if (dumper == null)
            throw new Exception("Il2CppDumper output not configured. Please run configuration script first.");
        
        if (dumper.typesByCName.isEmpty())
            throw new Exception("Failed to parse Il2CppDumper output. Check if path is correct.");

        DecompInterface decomp = new DecompInterface();
        try {
            String funcName = func.getName();
            monitor.setMessage("Decompiling " + funcName + "...");
            logger.info("Decompiling function: " + funcName);
            decomp.openProgram(currentProgram);

            // Настройка опций (сокращено для краткости, скопируй из скрипта)
            DecompileOptions options = new DecompileOptions();
            var toolOpts = new ToolOptions("Decompiler");
            toolOpts.setBoolean("Analysis.Simplify predication", true);
            toolOpts.setBoolean("Display.Print 'NULL' for null pointers", true);
            toolOpts.setBoolean("Display.Disable printing of type casts", true);
            options.grabFromToolAndProgram(null, toolOpts, currentProgram);
            decomp.setOptions(options);
            decomp.toggleCCode(true);
            decomp.toggleSyntaxTree(true);
            decomp.setSimplificationStyle("decompile");

            var results = decomp.decompileFunction(func, 30, monitor);
            splitAllVars();
            String rawCCode = results.getDecompiledFunction().getC();

            // Сохраняем C код
            String filePrefix = "results/" + funcName + "/";
            workspace.saveFile(filePrefix + "decompGhidra.c", rawCCode);

            String simplifiedCCode = sanitizer.sanitizeForCs(rawCCode, true);

            // Контекст
            String typeCName = findTypeCName(rawCCode);
            DecompiledType typeContext =
                (typeCName != null) ? dumper.typesByCName.get(typeCName) : null;

            String prompt = generatePrompt(simplifiedCCode, rawCCode, typeContext);
            workspace.saveFile(filePrefix + "llm_prompt.md", prompt);

            // LLM Call
            // ManualLLMClient использует SwingUtilities.invokeAndWait внутри, 
            // поэтому его безопасно вызывать даже из Task (хотя Task не в EDT)
            monitor.setMessage("Waiting for LLM...");
            List<LLMMessage> history = new ArrayList<>();
            String response = llmClient.chat(history, prompt);

            // Parsing
            String finalCsCode = extractCodeBlock(response, typeContext != null ? typeContext.namespace : null);
            workspace.saveFile(filePrefix + "decompLlm.cs", finalCsCode);

        }
        finally {
            decomp.dispose();
        }
    }

    private static void splitAllVars() {
        // TODO
    }

    private String findTypeCName(String cCode) {
        Matcher m = Pattern.compile("(\\w+?)__\\w+[\\s\\n]*\\(").matcher(cCode);
        return m.find() ? m.group(1) : null;
    }

private String generatePrompt(String simplifiedCode, String rawCode, DecompiledType type) {
    StringBuilder typeContextStr = new StringBuilder();
    
    if (dumper != null) {
        var usedTypes = dumper.typeKeys.search(rawCode);
        for (var typeCName : usedTypes) {
            var usedType = dumper.typesByCName.get(typeCName);
            if (usedType == null) continue;
            
            typeContextStr.append(usedType.heading).append("{\n");
            for (var itemCName : usedType.items.keySet()) {
                if (rawCode.contains(itemCName)) {
                    typeContextStr.append(usedType.items.get(itemCName));
                }
            }
            typeContextStr.append("}\n");
        }
    }
    
    return """
            This is a method of a Unity IL2CPP game decompiled using ghidra and I want you to rewrite it in C#.
            
            Rules:
            - Remove all ThrowFooException logic (e.g. null checks).
            - Translate `(var->fields).prop` to `var.prop`.
            - Remove `MethodInfo` arguments.
            - Ignore Ghidra artifacts like `_0_8_` fields or `SUB84` functions.
            - Simplify logic (don't set vars used once).
            - Output ONLY C# code in a markdown block.

            Ghidra C Code:
            ```c
            %s
            ```

            Context C# Types:
            ```csharp
            %s
            ```
            """.formatted(simplifiedCode, typeContextStr.toString());
}

    private String extractCodeBlock(String response, String namespace) {
        int start = response.indexOf("```");
        if (start == -1) return response;
        int codeStart = response.indexOf('\n', start) + 1;
        int end = response.lastIndexOf("```");
        if (end <= codeStart) return response;

        String codeBlock = response.substring(codeStart, end).trim();

        if(namespace != null && !namespace.isEmpty()){
            return "namespace " + namespace + " {\n" + codeBlock + "\n}\n";
        }

        return codeBlock;
    }

    private Logger createLogger() {
        ConsoleService consoleService = tool.getService(ConsoleService.class);

        return new Logger() {
            @Override
            public void info(String message) {
                consoleService.println("[INFO] " + message);
            }
            
            @Override
            public void warn(String message) {
                consoleService.println("[WARN] " + message);
            }
            
            @Override
            public void error(String message) {
                consoleService.println("[ERROR] " + message);
            }
        };
    }
}