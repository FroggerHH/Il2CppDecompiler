package il2cppdecompiler.plugin;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import il2cppdecompiler.codeprocessing.CodeDecompiler;
import il2cppdecompiler.codeprocessing.DumperParser;
import il2cppdecompiler.llm.ILLMClient;
import il2cppdecompiler.llm.llm_clients.OpenAIClientImpl;
import il2cppdecompiler.llm.llm_clients.OpenAIConfig;
import il2cppdecompiler.util.Logger;
import il2cppdecompiler.util.ProjectWorkspace;

import java.io.File;
import java.io.IOException;
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
    private CodeDecompiler decompiler;
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
            public void actionPerformed(ActionContext context) {
                provider.setVisible(true);
            }
        };
        action.setMenuBarData(
            new MenuData(new String[] { "Tools", "Il2Cpp", "Show C# Viewer" }, null, "Il2Cpp"));
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

        OpenAIConfig config = new OpenAIConfig(
            System.getenv("AI_API_KEY"),
            "google/gemini-3-flash-preview",
            "https://routerai.ru/api/v1");
        llmClient = new OpenAIClientImpl(config);
        // llmClient = new ManualLLMClient();

        startParsingDumperOutput();

        decompiler = new CodeDecompiler(dumper, llmClient, workspace, currentProgram, logger);
    }

    private void startParsingDumperOutput() {
        String dumperPath;
        try {
            dumperPath = workspace.getIl2CppDumperOutputDir();
        }
        catch (IOException e) {
            logger.error(e, "Failed to load project config: ");
            e.printStackTrace();
            return;
        }

        if (dumperPath == null) {
            SwingUtilities.invokeLater(() -> provider
                    .setLoadingState("Il2Cpp dump not found. Please configure the dumper path."));
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

                SwingUtilities.invokeLater(() -> {
                    locationChanged(currentLocation);
                });
            }
            catch (Exception e) {
                isReady = false;
                logger.error(e, "Failed to parse Il2CppDumper output");
                e.printStackTrace();
                SwingUtilities.invokeLater(
                    () -> provider.setLoadingState("Failed to parse Il2CppDumper output"));
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

        Function func = null;
        if (loc != null)
            func = loc.getProgram().getFunctionManager().getFunctionContaining(loc.getAddress());

        provider.updateLocation(func, workspace, isReady);
    }

    public void decompileFunction(Function func, Runnable onComplete) {
        Task task = decompiler.decompileFunction(func, onComplete);
        new TaskLauncher(task, provider.getComponent());
    }

    public ProjectWorkspace getWorkspace() {
        return workspace;
    }

    private Logger createLogger() {
        ConsoleService consoleService = tool.getService(ConsoleService.class);

        return new Logger() {
            @Override
            public void debug(String message) {
                consoleService.println("[DEBUG] " + message);
            }
            
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