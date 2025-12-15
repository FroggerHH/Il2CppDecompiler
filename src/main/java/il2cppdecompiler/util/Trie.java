package il2cppdecompiler.util;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Fast string searcher for when there are a lot of possible strings to be
 * found in a larger string.
 */
public class Trie {
    private static class Node {
        Map<Character, Node> children = new HashMap<>();
        boolean isEnd = false;
    }

    private Node root = new Node();

    public void insert(String key) {
        var node = root;
        for (var ch : key.toCharArray()) {
            node = node.children.computeIfAbsent(ch, k -> new Node());
        }
        node.isEnd = true;
    }

    /** Is greedy and non-overlapping. */
    public Set<String> search(String str) {
        var result = new HashSet<String>();
        for (int i = 0, len = str.length(); i < len;) {
            var node = root;
            var curMatch = new StringBuilder();
            String longestMatch = null;

            for (var j = i; j < len; j++) {
                var ch = str.charAt(j);
                node = node.children.get(ch);
                if (node == null) {
                    break;
                }
                curMatch.append(ch);
                if (node.isEnd) {
                    longestMatch = curMatch.toString();
                }
            }

            if (longestMatch != null) {
                result.add(longestMatch);
                i += longestMatch.length();
            }
            else {
                i++;
            }
        }
        return result;
    }
}