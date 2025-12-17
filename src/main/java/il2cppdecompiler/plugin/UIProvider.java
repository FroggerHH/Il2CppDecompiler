package il2cppdecompiler.plugin;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Function;
import il2cppdecompiler.util.ProjectWorkspace;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;

public class UIProvider extends ComponentProviderAdapter {
    private Il2CppDecompilerPlugin plugin;
    private JPanel mainPanel;
    private CardLayout cardLayout;

    private JTextArea codeArea;
    private JLabel statusLabel;
    private JButton decompileButton;
    private JLabel loadingLabel;

    private Function currentFunction;

    public UIProvider(Il2CppDecompilerPlugin plugin, String owner) {
        super(plugin.getTool(), "Il2Cpp C# Viewer", owner);
        this.plugin = plugin;

        setTitle("Il2Cpp C# Decompiler");
        setWindowGroup("Il2Cpp");
        setIcon(ResourceManager.loadImage("images/csharp-logo.png"));

        buildPanelUi();

        addToTool();
    }

    private void buildPanelUi() {
        cardLayout = new CardLayout();
        mainPanel = new JPanel(cardLayout);

        // 1. View: Empty / Info
        JPanel infoPanel = new JPanel(new GridBagLayout());
        statusLabel = new JLabel("Select a function to view C# code");
        statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
        infoPanel.add(statusLabel);

        // 2. View: Action Button
        JPanel actionPanel = new JPanel(new GridBagLayout());
        JPanel innerAction = new JPanel(new BorderLayout(0, 10));
        JLabel actionLabel = new JLabel("LLM Decompilation not cached for this function.");
        actionLabel.setHorizontalAlignment(SwingConstants.CENTER);
        decompileButton = new JButton("Decompile with LLM");
        decompileButton.addActionListener(e -> requestDecompilation());

        innerAction.add(actionLabel, BorderLayout.NORTH);
        innerAction.add(decompileButton, BorderLayout.SOUTH);
        actionPanel.add(innerAction);

        // 3. View: Code Viewer
        codeArea = new JTextArea();
        codeArea.setEditable(false);
        codeArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane codeScroll = new JScrollPane(codeArea);

        // 4. View: Loading
        JPanel loadingPanel = new JPanel(new GridBagLayout());
        JPanel innerLoading = new JPanel(new BorderLayout(0, 10));
        loadingLabel = new JLabel("Initializing...");
        loadingLabel.setHorizontalAlignment(SwingConstants.CENTER);
        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        innerLoading.add(loadingLabel, BorderLayout.NORTH);
        innerLoading.add(progressBar, BorderLayout.SOUTH);
        loadingPanel.add(innerLoading);

        // // 5. View: Settings
        // JPanel settingsPanel = new JPanel(new GridBagLayout());
        // JLabel statusLabel = new JLabel("Settings");
        // statusLabel.setHorizontalAlignment(SwingConstants.TOP);
        // statusLabel.setVerticalAlignment(SwingConstants.TOP);
        // settingsPanel.add(statusLabel);

        // Add cards
        mainPanel.add(infoPanel, "INFO");
        mainPanel.add(actionPanel, "ACTION");
        mainPanel.add(codeScroll, "CODE");
        mainPanel.add(loadingPanel, "LOADING");
        mainPanel.add(loadingPanel, "LOADING");
        // mainPanel.add(settingsPanel, "SETTINGS");
    }

    public void setLoadingState(String message) {
        loadingLabel.setText(message);
        cardLayout.show(mainPanel, "LOADING");
    }

    public void updateLocation(Function func, ProjectWorkspace workspace, boolean isReady) {
        this.currentFunction = func;

        if (!isReady) {
            setLoadingState("Parsing Il2Cpp Dump...");
            return;
        }

        if (func == null) {
            statusLabel.setText("Select a function to start");
            cardLayout.show(mainPanel, "INFO");
            return;
        }

        if (workspace.hasDecompiledCs(func)) {
            try {
                String code = workspace.loadDecompiledCs(func);
                codeArea.setText(code);
                codeArea.setCaretPosition(0);
                cardLayout.show(mainPanel, "CODE");
            }
            catch (IOException e) {
                statusLabel.setText("Error reading file: " + e.getMessage());
                cardLayout.show(mainPanel, "INFO");
            }
        }
        else {
            decompileButton.setText("Decompile '" + func.getName() + "' with LLM");
            decompileButton.setEnabled(true);
            cardLayout.show(mainPanel, "ACTION");
        }
    }

    private void requestDecompilation() {
        if (currentFunction == null)
            return;

        decompileButton.setEnabled(false);
        decompileButton.setText("Decompiling...");

        plugin.decompileFunction(currentFunction, () -> 
            SwingUtilities.invokeLater(() -> updateLocation(currentFunction, plugin.getWorkspace(), true)));
    }

    @Override
    public JComponent getComponent() { return mainPanel; }
}