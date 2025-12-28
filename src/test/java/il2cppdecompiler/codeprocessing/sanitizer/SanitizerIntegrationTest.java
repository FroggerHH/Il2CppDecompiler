package il2cppdecompiler.codeprocessing.sanitizer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import il2cppdecompiler.util.Logger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

// ==== !!! ВНИМАНИЕ !!! ====
// 
// Это тесты "works on my machine". Для из корректной работы необходимо развернуть в Гидре 
// исходники код конкретной игры. При желании закиньте в "GHIDRA_SANITIZER_TEST_PROJECT_DIR"
// путь к проанализированному проекту другой игры и распишите свои тесты под неё в "sanitizer-tests.json"
// 
// ==== !!! ВНИМАНИЕ !!! ====


class SanitizerIntegrationTest {

    private static final String CONFIG_PATH = "src/test/resources/fixtures/sanitizer/sanitizer-tests.json";
    private static final String FIXTURES_DIR = "src/test/resources/fixtures/sanitizer";

    private static GhidraTestContext ghidraContext;
    private static DecompInterface decompInterface;
    private static ProcessorFactory processorFactory;

    private static Logger logger;

    @BeforeAll
    static void setupGhidra() throws Exception {
        logger = new Logger() {
            @Override
            public void debug(String message) {
                System.out.println("[DEBUG] " + message);
            }
            
            @Override
            public void info(String message) {
                System.out.println("[INFO] " + message);
            }

            @Override
            public void warn(String message) {
                System.out.println("[WARN] " + message);
            }

            @Override
            public void error(String message) {
                System.err.println("[ERROR] " + message);
            }

            @Override
            public void error(Exception exception, String message) {
                System.err.println("[ERROR] " + message + ": " + exception.getMessage());
            }
        };

        String projectDir = System.getenv("GHIDRA_SANITIZER_TEST_PROJECT_DIR");
        if (projectDir == null || projectDir.isEmpty()) {
            System.err.println("GHIDRA_SANITIZER_TEST_PROJECT_DIR environment variable is not set");
            throw new RuntimeException(
                "GHIDRA_SANITIZER_TEST_PROJECT_DIR environment variable is not set");
        }

        System.out.println(" [>] Creating GhidraTestContext");
        ghidraContext = new GhidraTestContext(projectDir, "GameAssembly.dll");

        decompInterface = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        var toolOpts = new ToolOptions("Decompiler");
        toolOpts.setBoolean("Analysis.Simplify predication", true);
        toolOpts.setBoolean("Display.Print 'NULL' for null pointers", true);
        toolOpts.setBoolean("Display.Disable printing of type casts", true);
        decompInterface.setOptions(options);
        decompInterface.toggleCCode(true);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("decompile");

        if (!decompInterface.openProgram(ghidraContext.getProgram())) {
            throw new RuntimeException(
                "Decompiler failed to open program: " + decompInterface.getLastMessage());
        }

        processorFactory = new ProcessorFactory(logger);

        System.out.println(" [+] BeforeAll finished");
    }

    @AfterAll
    static void tearDownGhidra() {
        if (decompInterface != null) {
            decompInterface.dispose();
        }
        if (ghidraContext != null) {
            ghidraContext.close();
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("provideTestFixtures")
    void testSanitizerFixture(SanitizerTestFixture fixture) throws IOException {
        System.out.println("\n========================================");
        System.out.println("Test: " + fixture.name);
        System.out.println("Function: " + fixture.functionName);
        System.out.println("Processors: " + fixture.processors);
        System.out.println("========================================");

        Function func = ghidraContext.findFunction(fixture.functionName);
        assertNotNull(func, "Function not found in Ghidra: " + fixture.functionName);

        DecompileResults results = decompInterface.decompileFunction(func, 30, TaskMonitor.DUMMY);
        assertNotNull(results, "Decompile results are null for " + fixture.functionName);
        System.out.println("\n[ORIGINAL]\n" + results.getDecompiledFunction().getC());

        CodeContext context = new CodeContext(results);

        SanitizerPipeline pipeline = new SanitizerPipeline();
        for (String processorName : fixture.processors) {    
            ICodeProcessor processor = processorFactory.createProcessor(processorName);
            pipeline.addProcessor(processor);
        }

        pipeline.execute(context);
        String sanitizedCode = context.generateSourceCode();
        System.out.println("\n[SANITIZED]\n" + sanitizedCode);

        Path expectedFilePath = Paths.get(FIXTURES_DIR, fixture.expectedFile);
        assertNotNull(expectedFilePath, "Expected file not found: " + expectedFilePath);
        String expectedCode = Files.readString(expectedFilePath);
        System.out.println("\n[EXPECTED]\n" + expectedCode);

        assertEquals(
            expectedCode.trim().replace("\r\n", "\n"),
            sanitizedCode.trim().replace("\r\n", "\n"),
            "Sanitized code does not match expected output for: " + fixture.name
        );

        System.out.println("\n✓ PASSED");
    }

    private static Stream<SanitizerTestFixture> provideTestFixtures() throws IOException {
        Path configPath = Paths.get(CONFIG_PATH);
        if (!Files.exists(configPath)) {
            System.err.println("Config file not found: " + configPath);
            return Stream.empty();
        }

        SanitizerTestConfig config = SanitizerTestConfig.loadFromJsonFile(configPath);
        
        return config.tests.stream()
            .sorted(Comparator.comparing(t -> t.name))
            .peek(test -> System.out.println(" [+] Test loaded: " + test.name));
    }
}