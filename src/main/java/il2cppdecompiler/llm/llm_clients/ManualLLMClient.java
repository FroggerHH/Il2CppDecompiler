package il2cppdecompiler.llm.llm_clients;

import il2cppdecompiler.llm.ILLMClient;
import il2cppdecompiler.llm.LLMMessage;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class ManualLLMClient implements ILLMClient {

    @Override
    public String getName() { return "Manual Copy-Paste"; }

    @Override
    public String chat(List<LLMMessage> history, String prompt) throws Exception {
        showRequestDialog(prompt);
        return showResponseDialog();
    }

    private void showRequestDialog(String content) throws Exception {
        final AtomicBoolean wasCancelled = new AtomicBoolean(false);
        final CountDownLatch latch = new CountDownLatch(1);

        SwingUtilities.invokeLater(() -> {
            try {
                JDialog dialog = new JDialog((Frame) null, "LLM Request (Copy this)", true);
                dialog.setSize(800, 600);
                dialog.setLocationRelativeTo(null);
                
                JTextArea textArea = new JTextArea(content);
                textArea.setEditable(false);
                textArea.setLineWrap(true);
                
                JButton copyBtn = new JButton("Copy to Clipboard");
                copyBtn.addActionListener(e -> {
                    copyToClipboard(content);
                    JOptionPane.showMessageDialog(dialog, "Copied! Paste to AI.", "Success", JOptionPane.INFORMATION_MESSAGE);
                    dialog.dispose();
                    latch.countDown();
                });

                dialog.setLayout(new BorderLayout());
                dialog.add(new JScrollPane(textArea), BorderLayout.CENTER);
                dialog.add(copyBtn, BorderLayout.SOUTH);
                
                dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        wasCancelled.set(true);
                        latch.countDown();
                    }
                });
                
                dialog.setVisible(true);
            } catch (Exception e) {
                wasCancelled.set(true);
                latch.countDown();
            }
        });

        latch.await();
        if (wasCancelled.get()) throw new Exception("User cancelled request dialog");
    }

    private String showResponseDialog() throws Exception {
        final AtomicReference<String> result = new AtomicReference<>(null);
        final AtomicBoolean wasCancelled = new AtomicBoolean(false);
        final CountDownLatch latch = new CountDownLatch(1);

        SwingUtilities.invokeLater(() -> {
            JDialog dialog = new JDialog((Frame) null, "LLM Response (Paste here)", true);
            dialog.setSize(800, 600);
            dialog.setLocationRelativeTo(null);

            JTextArea textArea = new JTextArea();
            textArea.setLineWrap(true);

            JButton submitBtn = new JButton("Submit");
            submitBtn.addActionListener(e -> {
                result.set(textArea.getText());
                dialog.dispose();
                latch.countDown();
            });
            
            JButton pasteBtn = new JButton("Paste");
            pasteBtn.addActionListener(e -> textArea.setText(getClipboardContent()));

            JPanel panel = new JPanel();
            panel.add(pasteBtn);
            panel.add(submitBtn);

            dialog.setLayout(new BorderLayout());
            dialog.add(new JScrollPane(textArea), BorderLayout.CENTER);
            dialog.add(panel, BorderLayout.SOUTH);

            dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                public void windowClosing(java.awt.event.WindowEvent e) {
                    wasCancelled.set(true);
                    latch.countDown();
                }
            });

            dialog.setVisible(true);
        });

        latch.await();
        if (wasCancelled.get()) throw new Exception("User cancelled response dialog");
        String res = result.get();
        if (res == null || res.isBlank()) throw new Exception("Empty response");
        return res;
    }

    private void copyToClipboard(String text) {
        StringSelection selection = new StringSelection(text);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(selection, null);
    }
    
    private String getClipboardContent() {
        try {
            return (String) Toolkit.getDefaultToolkit().getSystemClipboard()
                .getData(java.awt.datatransfer.DataFlavor.stringFlavor);
        } catch (Exception e) {
            return "";
        }
    }
}