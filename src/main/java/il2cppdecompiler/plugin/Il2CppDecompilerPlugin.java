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
import il2cppdecompiler.codeprocessing.CodeSanitizer;
import il2cppdecompiler.codeprocessing.DecompiledType;
import il2cppdecompiler.codeprocessing.DumperParser;
import il2cppdecompiler.llm.ILLMClient;
import il2cppdecompiler.llm.LLMMessage;
import il2cppdecompiler.llm.llm_clients.ManualLLMClient;
import il2cppdecompiler.util.Logger;
import il2cppdecompiler.util.ProjectWorkspace;

import java.io.File;
import java.io.IOException;
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
) //@formatter:on
public class Il2CppDecompilerPlugin extends ProgramPlugin {

    private UIProvider provider;

    private volatile boolean isReady = false;

    // Services
    private ProjectWorkspace workspace;
    private CodeSanitizer sanitizer;
    private DumperParser dumper;
    private ILLMClient llmClient;
    private Logger logger;

    public Il2CppDecompilerPlugin(PluginTool tool) {
        super(tool);
        String pluginName = getName();
        provider = new UIProvider(this, pluginName);
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
            public void actionPerformed(ActionContext context) { provider.setVisible(true); }
        };
        action.setMenuBarData(new MenuData(new String[] { "Tools", "Il2Cpp", "Show C# Viewer" }, null, "Il2Cpp"));
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
        isReady = false;

        File projectDir = program.getDomainFile().getParent().getProjectLocator().getProjectDir();
        workspace = new ProjectWorkspace(projectDir);
        sanitizer = new CodeSanitizer();
        llmClient = new ManualLLMClient();

        startParsingDumperOutput();
    }

    private void startParsingDumperOutput() {
        String dumperPath;
        try {
            dumperPath = workspace.getIl2CppDumperOutputDir();
        } catch (IOException e) {
            logger.error(e, "Failed to load project config: ");
            e.printStackTrace();
            return;
        }

        if (dumperPath == null) {
        SwingUtilities.invokeLater(() -> provider.setLoadingState("Il2Cpp dump not found. Please configure the dumper path."));
            logger.warn("Il2Cpp dumper output directory not configured");
            isReady = true;
            return;
        }

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
                isReady = false;
                logger.error(e, "Failed to parse Il2CppDumper output");
                e.printStackTrace();
                SwingUtilities.invokeLater(() -> provider.setLoadingState("Failed to parse Il2CppDumper output"));
            }
        }).start();
    }

    @Override
    protected void locationChanged(ProgramLocation loc) {
        if (provider == null) {
            logger.warn("Provider is not initialized yet");
            return;
        }
        
        if (workspace == null) {
            logger.warn("Workspace is not initialized yet");
            return;
        }

        // if (provider.isVisible()) return;

        Function func = null;
        if (loc != null)
            func = loc.getProgram().getFunctionManager().getFunctionContaining(loc.getAddress());

        provider.updateLocation(func, workspace, isReady);
    }

    public ProjectWorkspace getWorkspace() {
        return workspace;
    }

    public void decompileFunction(Function func, Runnable onComplete) {
        Task task = new Task("LLM Decompilation", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    doDecompile(func, monitor);
                }
                catch (Exception e) {
                    logger.error(e, "Decompilation failed");
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

            String filePrefix = "results/" + funcName + "/";
            workspace.saveFile(filePrefix + "decompGhidra.c", rawCCode);

            String simplifiedCCode = sanitizer.sanitizeForCs(rawCCode, true);

            String typeCName = findTypeCName(rawCCode);
            DecompiledType typeContext =
                (typeCName != null) ? dumper.typesByCName.get(typeCName) : null;

            String prompt = generatePrompt(simplifiedCCode, rawCCode, typeContext);
            workspace.saveFile(filePrefix + "llm_prompt.md", prompt);

            monitor.setMessage("Waiting for LLM...");
            List<LLMMessage> history = new ArrayList<>();
            String response = llmClient.chat(history, prompt);

            // Parsing
            String finalCsCode = extractCodeBlock(response, typeContext != null ? typeContext.namespace : null);
            workspace.saveFile(filePrefix + "decompLlm.cs", finalCsCode);

        }
        catch (Exception e) {
            logger.error(e, "Decompilation error");
            ghidra.util.Msg.showError(this, null, "Decompilation Error", e.getMessage(), e);
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

        consoleService.printError(name);

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
                consoleService.printlnError("[ERROR] " + message);
            }
            
            @Override
            public void error(Exception exception, String message) {
                consoleService.printlnError("[ERROR] " + message + ": " + exception.getMessage());
            }
        };
    }
}