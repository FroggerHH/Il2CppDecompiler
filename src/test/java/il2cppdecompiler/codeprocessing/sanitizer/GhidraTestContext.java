package il2cppdecompiler.codeprocessing.sanitizer;

import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.base.project.GhidraProject;

import java.io.File;
import java.io.IOException;

public class GhidraTestContext implements AutoCloseable {
    private GhidraProject ghidraProject;
    private Program program;

    public static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration conf = new HeadlessGhidraApplicationConfiguration();
            Application.initializeApplication(new ghidra.GhidraApplicationLayout(), conf);
        }
    }

    public GhidraTestContext(String projectDirPath, String programName) throws Exception {
        initializeGhidra();
        File projectDir = new File(projectDirPath);
        if (!projectDir.exists()) {
            throw new IOException("Project directory does not exist: " + projectDirPath);
        }

        // GhidraProject.openProject expects the directory containing the .gpr file and the project name (without .gpr)
        String parentDir = projectDir.getParent();
        String projectName = projectDir.getName();
        if (projectName.endsWith(".rep")) {
            projectName = projectName.substring(0, projectName.length() - 4);
        } else if (projectName.endsWith(".gpr")) {
            projectName = projectName.substring(0, projectName.length() - 4);
        }

        ghidraProject = GhidraProject.openProject(parentDir, projectName, false);
        program = ghidraProject.openProgram("/", programName, false);
        
        if (program == null) {
            throw new IOException("Could not find program " + programName + " in project " + projectDirPath);
        }
    }

    public Program getProgram() {
        return program;
    }

    public Function findFunction(String name) {
        if (program == null) {
            return null;
        }
        FunctionIterator iter = program.getFunctionManager().getFunctions(true);
        for (Function f : iter) {
            if (f.getName().equals(name)) {
                return f;
            }
        }
        return null;
    }

    @Override
    public void close() {
        if (program != null) {
            // GhidraProject handles the consumer when opening the program
            ghidraProject.close(program);
        }
        if (ghidraProject != null) {
            ghidraProject.close();
        }
    }
}
