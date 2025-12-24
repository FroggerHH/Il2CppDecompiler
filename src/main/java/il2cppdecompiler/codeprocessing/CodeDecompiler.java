package il2cppdecompiler.codeprocessing;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import il2cppdecompiler.codeprocessing.sanitizer.CodeSanitizer;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import il2cppdecompiler.llm.ILLMClient;
import il2cppdecompiler.llm.LLMMessage;
import il2cppdecompiler.util.Logger;
import il2cppdecompiler.util.ProjectWorkspace;

public class CodeDecompiler {
    private final DumperParser dumper;
    private final Logger logger;
    private final ILLMClient llmClient;
    private final Program currentProgram;
    private final ProjectWorkspace workspace;

    public CodeDecompiler(DumperParser dumper, ILLMClient llmClient, ProjectWorkspace workspace,
            Program currentProgram, Logger logger) {
        this.dumper = dumper;
        this.logger = logger;
        this.llmClient = llmClient;
        this.currentProgram = currentProgram;
        this.workspace = workspace;
    }

    public Task decompileFunction(Function func, Runnable onComplete) {
        return new Task("LLM Decompilation", true, true, true) {
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
    }

    private void doDecompile(Function func, TaskMonitor monitor) throws Exception {
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

            DecompileResults cDecompileResults = decomp.decompileFunction(func, 30, monitor);
            String rawCCode = cDecompileResults.getDecompiledFunction().getC();

            String filePrefix = "results/" + funcName + "/";
            workspace.saveFile(filePrefix + "decompGhidra.c", rawCCode);

            String simplifiedCCode = CodeSanitizer.processCCode(cDecompileResults);

            String typeCName = findTypeCName(rawCCode);
            DecompiledType typeContext =
                (typeCName != null) ? dumper.typesByCName.get(typeCName) : null;

            String prompt = generatePrompt(simplifiedCCode, rawCCode, typeContext);
            workspace.saveFile(filePrefix + "llm_prompt.md", prompt);

            monitor.setMessage("Waiting for LLM...");
            List<LLMMessage> history = new ArrayList<>();
            String response = llmClient.chat(history, prompt);

            // Parsing
            String finalCsCode =
                extractCodeBlock(response, typeContext != null ? typeContext.namespace : null);
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
                if (usedType == null)
                    continue;

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
                """
                .formatted(simplifiedCode, typeContextStr.toString());
    }

    private String extractCodeBlock(String response, String namespace) {
        int start = response.indexOf("```");
        if (start == -1)
            return response;
        int codeStart = response.indexOf('\n', start) + 1;
        int end = response.lastIndexOf("```");
        if (end <= codeStart)
            return response;

        String codeBlock = response.substring(codeStart, end).trim();

        if (namespace != null && !namespace.isEmpty()) {
            return "namespace " + namespace + " {\n" + codeBlock + "\n}\n";
        }

        return codeBlock;
    }

}
