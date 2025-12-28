package il2cppdecompiler.codeprocessing.sanitizer.util;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.ClangTypeToken;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangCommentToken;

import java.util.List;

public class AstVisualizer {
    private static final String BRANCH = "├── ";
    private static final String LAST_BRANCH = "└── ";
    private static final String VERTICAL = "│   ";
    private static final String SPACE = "    ";
    
    private static final String RESET = "\u001B[0m";
    private static final String GRAY = "\u001B[90m";
    private static final String BLUE = "\u001B[34m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String CYAN = "\u001B[36m";
    private static final String MAGENTA = "\u001B[35m";
    private static final String RED = "\u001B[31m";
    private static final String BOLD = "\u001B[1m";
    
    private final boolean useColors;
    private final int maxDepth;
    private final boolean showPositions;
    private final boolean showEmpty;
    
    private AstVisualizer(boolean useColors, int maxDepth, boolean showPositions, boolean showEmpty) {
        this.useColors = useColors;
        this.maxDepth = maxDepth;
        this.showPositions = showPositions;
        this.showEmpty = showEmpty;
    }
    
    /**
     * Visualizes the AST tree with default settings
     * @param root the root AST node
     */
    public static void visualize(ClangTokenGroup root) {
        new AstVisualizer(true, Integer.MAX_VALUE, false, false).print(root);
    }

    /**
     * Visualizes the AST tree with custom settings
     * @param root the root AST node
     * @param useColors use ANSI colors
     * @param maxDepth maximum depth to display
     * @param showPositions show positions in source code
     * @param showEmpty show empty tokens (whitespace, newlines)
     */
    public static void visualize(ClangTokenGroup root, boolean useColors, 
                                 int maxDepth, boolean showPositions, boolean showEmpty) {
        new AstVisualizer(useColors, maxDepth, showPositions, showEmpty).print(root);
    }
    
    private void print(ClangTokenGroup root) {
        if (root == null) {
            System.out.println(color(RED, "⚠ AST root is null"));
            return;
        }
        
        System.out.println();
        System.out.println(color(BOLD + CYAN, "╔════════════════════════════════════════════╗"));
        System.out.println(color(BOLD + CYAN, "║") + color(BOLD, "          AST Tree Visualization            ") + 
                           color(BOLD + CYAN, "║"));
        System.out.println(color(BOLD + CYAN, "╚════════════════════════════════════════════╝"));
        System.out.println();
        
        printNode(root, "", true, 0);
        
        System.out.println();
        System.out.println(color(GRAY, "─".repeat(50)));
        System.out.println(color(BOLD, "Legend:") + 
                          color(BLUE, " Group") + " | " +
                          color(GREEN, "Function") + " | " +
                          color(YELLOW, "Variable") + " | " +
                          color(MAGENTA, "Type") + " | " +
                          color(CYAN, "Field") + " | " +
                          color(GRAY, "Token"));
        System.out.println();
    }
    
    private void printNode(ClangNode node, String prefix, boolean isLast, int depth) {
        if (node == null) {
            System.out.println(prefix + (isLast ? LAST_BRANCH : BRANCH) + color(RED, "⚠ null"));
            return;
        }
        
        if (depth >= maxDepth) {
            System.out.println(prefix + (isLast ? LAST_BRANCH : BRANCH) + color(GRAY, "... (max depth reached)"));
            return;
        }
        
        String connector = isLast ? LAST_BRANCH : BRANCH;
        System.out.print(prefix + connector);
        printNodeInfo(node, depth);
        System.out.println();
        
        if (!(node instanceof ClangTokenGroup)) return; 

        ClangTokenGroup group = (ClangTokenGroup) node;
        List<ClangNode> children = AstUtils.getChildren(group);
        
        if (children.isEmpty()) {
            String childPrefix = prefix + (isLast ? SPACE : VERTICAL);
            System.out.println(childPrefix + color(GRAY, "└─ (empty)"));
            return;
        }
        
        List<ClangNode> filteredChildren = children;
        if (!showEmpty) {
            filteredChildren = children.stream()
                .filter(child -> !(child instanceof ClangToken) || !isEmptyToken((ClangToken) child))
                .toList();
        }
        
        for (int i = 0; i < filteredChildren.size(); i++) {
            ClangNode child = filteredChildren.get(i);
            boolean isLastChild = (i == filteredChildren.size() - 1);
            String childPrefix = prefix + (isLast ? SPACE : VERTICAL);
            printNode(child, childPrefix, isLastChild, depth + 1);
        }
    }
    
    private void printNodeInfo(ClangNode node, int depth) {
        String typeInfo = getNodeTypeInfo(node);
        String contentInfo = getNodeContentInfo(node);
        String positionInfo = showPositions ? getPositionInfo(node) : "";
        
        System.out.print(typeInfo);
        if (!contentInfo.isEmpty())
            System.out.print(" " + contentInfo);
        if (!positionInfo.isEmpty())
            System.out.print(" " + color(GRAY, positionInfo));
        
        if (node instanceof ClangTokenGroup) {
            ClangTokenGroup group = (ClangTokenGroup) node;
            int childCount = AstUtils.getChildren(group).size();
            System.out.print(" " + color(GRAY, "[" + childCount + " children]"));
        }
    }
    
    private String getNodeTypeInfo(ClangNode node) {
        if (node instanceof ClangFuncNameToken) return color(BOLD + GREEN, "⚙ Function");
        else if (node instanceof ClangVariableToken) return color(YELLOW, "◆ Variable");
        else if (node instanceof ClangTypeToken) return color(MAGENTA, "▣ Type");
        else if (node instanceof ClangFieldToken) return color(CYAN, "⬥ Field");
        else if (node instanceof ClangCommentToken) return color(GRAY, "💬 Comment");
        else if (node instanceof ClangTokenGroup) {
            ClangTokenGroup group = (ClangTokenGroup) node;
            return color(BLUE, "📦 Group") + color(GRAY, "(" + getGroupTypeName(group) + ")");
        } else if (node instanceof ClangToken) return color(GRAY, "○ Token");
        else return color(RED, "? Unknown");
    }
    
    private String getNodeContentInfo(ClangNode node) {
        if (node instanceof ClangToken) {
            ClangToken token = (ClangToken) node;
            String text = token.getText();
            
            if (text == null) return color(GRAY, "∅");
            
            text = escapeString(text);
            
            if (text.length() > 60)
                text = text.substring(0, 57) + "...";
            
            if (text.trim().isEmpty()) {
                if (text.equals("\n")) return color(GRAY, "⏎ newline");
                else if (text.equals(" ")) return color(GRAY, "␣ space");
                else if (text.equals("\t")) return color(GRAY, "⇥ tab");
                else return color(GRAY, "⌴ whitespace(" + text.length() + ")");
            }
            
            return color(getContentColor(node), "\"" + text + "\"");
        }
        
        return "";
    }
    
    private String getContentColor(ClangNode node) {
        if (node instanceof ClangFuncNameToken) return BOLD + GREEN;
        if (node instanceof ClangVariableToken) return YELLOW;
        if (node instanceof ClangTypeToken) return MAGENTA;
        if (node instanceof ClangFieldToken) return CYAN;
        if (node instanceof ClangCommentToken) return GRAY;
        return RESET;
    }
    
    private String getGroupTypeName(ClangTokenGroup group) {
        return group.getClass().getSimpleName();

        // List<ClangNode> children = AstUtils.getChildren(group);
        
        // if (children.isEmpty()) {
        //     return "empty";
        // }
        
        // for (ClangNode child : children) {
        //     if (child instanceof ClangToken) {
        //         String text = ((ClangToken) child).getText();
        //         if (text != null && !text.trim().isEmpty()) {
        //             switch (text.trim()) {
        //                 case "if": return "if-statement";
        //                 case "while": return "while-loop";
        //                 case "for": return "for-loop";
        //                 case "do": return "do-while";
        //                 case "switch": return "switch";
        //                 case "return": return "return";
        //                 case "{": return "block";
        //                 case "(": return "expression";
        //             }
        //         }
        //     }
        // }
        
        // String fullText = group.toString().trim();
        // if (fullText.startsWith("{") && fullText.endsWith("}")) return "block";
        // if (fullText.contains("=")) return "assignment";
        // if (fullText.contains("(") && fullText.contains(")")) return "call/expr";
        
        // return "group";
    }
    
    private String getPositionInfo(ClangNode node) {
        if (node instanceof ClangToken) {
            ClangToken token = (ClangToken) node;
            int minAddress = token.getMinAddress() != null ? 
                (int) token.getMinAddress().getOffset() : -1;
            int maxAddress = token.getMaxAddress() != null ? 
                (int) token.getMaxAddress().getOffset() : -1;
                
            if (minAddress >= 0 || maxAddress >= 0) {
                return String.format("@[0x%x-0x%x]", minAddress, maxAddress);
            }
        }
        return "";
    }
    
    private boolean isEmptyToken(ClangToken token) {
        String text = token.getText();
        return text == null || text.trim().isEmpty();
    }
    
    private String escapeString(String str) {
        return str.replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t")
                  .replace("\"", "\\\"");
    }
    
    private String color(String colorCode, String text) {
        if (!useColors) {
            return text;
        }
        return colorCode + text + RESET;
    }
}