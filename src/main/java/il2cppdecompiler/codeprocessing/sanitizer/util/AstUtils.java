package il2cppdecompiler.codeprocessing.sanitizer.util;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.Stack;
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

    public static List<ClangToken> flattenChildrenToList(ClangNode group) {
        return flattenChildrenToList(group, true);
    }

    public static List<ClangToken> flattenChildrenToList(ClangNode root, boolean removeEmpty ) {
        List<ClangToken> result = new ArrayList<>();
        Stack<ClangNode> stack = new Stack<>();
        stack.push(root);

        while (!stack.isEmpty()) {
            ClangNode node = stack.pop();

            if (node instanceof ClangToken) {
                ClangToken token = (ClangToken) node;
                if (!removeEmpty || !isEmptyToken(token)) {
                    result.add(token);
                }
                continue;
            }

            if (node instanceof ClangTokenGroup) {
                ClangTokenGroup group = (ClangTokenGroup) node;
                List<ClangNode> children = getChildren(group);

                for (int i = children.size() - 1; i >= 0; i--) {
                    stack.push(children.get(i));
                }
            } // else result.add(node);
        }

        return result;
    }

    private static boolean isEmptyToken(ClangToken token) {
        String text = token.getText();
        return text == null || text.trim().isEmpty();
    }

    private static boolean isWhitespaceToken(ClangNode node) {
        if (node instanceof ClangToken) {
            String text = ((ClangToken) node).getText();
            return text != null && text.trim().isEmpty() && !text.contains("\n");
        }
        return false;
    }
}