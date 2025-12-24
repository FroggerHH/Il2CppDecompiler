package il2cppdecompiler.codeprocessing.sanitizer;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.function.Predicate;

public class AstUtils {
    private static Field tokGroupField;

    static {
        try {
            tokGroupField = ClangTokenGroup.class.getDeclaredField("tokgroup");
            tokGroupField.setAccessible(true);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    public static List<ClangNode> getChildren(ClangTokenGroup group) {
        if (group == null || tokGroupField == null) return Collections.emptyList();
        try {
            return (List<ClangNode>) tokGroupField.get(group);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            return Collections.emptyList();
        }
    }

    public static void removeNodes(ClangTokenGroup group, Predicate<ClangNode> predicate) {
        List<ClangNode> children = getChildren(group);
        children.removeIf(predicate);

        for (ClangNode child : children) {
            if (child instanceof ClangTokenGroup) {
                removeNodes((ClangTokenGroup) child, predicate);
            }
        }
    }

    public static void removeNodesWithCleanup(ClangTokenGroup group, Predicate<ClangNode> targetPredicate) {
        List<ClangNode> children = getChildren(group);
        ListIterator<ClangNode> it = children.listIterator();

        while (it.hasNext()) {
            ClangNode node = it.next();

            if (node instanceof ClangTokenGroup) {
                removeNodesWithCleanup((ClangTokenGroup) node, targetPredicate);
                continue;
            }

            if (targetPredicate.test(node)) {
                it.remove();

                while (it.hasPrevious()) {
                    ClangNode prev = it.previous();
                    if (isWhitespaceToken(prev)) {
                        it.remove();
                    } else {
                        it.next();
                        break;
                    }
                }
            }
        }
    }

    private static boolean isWhitespaceToken(ClangNode node) {
        if (node instanceof ClangToken) {
            String text = ((ClangToken) node).getText();
            return text != null && text.trim().isEmpty() && !text.contains("\n");
        }
        return false;
    }
}