package il2cppdecompiler.codeprocessing.sanitizer.processors.ast;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import il2cppdecompiler.codeprocessing.sanitizer.CodeContext;
import il2cppdecompiler.codeprocessing.sanitizer.ICodeProcessor;
import il2cppdecompiler.codeprocessing.sanitizer.util.AstUtils;
import il2cppdecompiler.util.Logger;

// if (DAT_044560b4 == '\0') {
//                   /* WARNING: Subroutine does not return */
//   EnsureInitializedOrSmt(&Albion_Common_Math_AxisAlignedRectangle_TypeInfo);
// }

public class TypeInitializationCheckRemover implements ICodeProcessor {

    private static final String DAT_PREFIX = "DAT_";
    private static final String TYPE_INFO_SUFFIX = "_TypeInfo";

    public TypeInitializationCheckRemover(Logger logger) {}

    @Override
    public void process(CodeContext context) {
        ClangTokenGroup root = context.getAstRoot();
        if (root == null) return;
        removeTypeInitChecks(root);
    }

    @Override public int getPriority() { return 30; }

    private void removeTypeInitChecks(ClangTokenGroup root) {
        if (root == null) return;

        List<ClangToken> tokens = AstUtils.flattenChildrenToList(root);
        if (tokens.isEmpty()) return;

        Set<ClangToken> tokensToRemove = findTypeInitCheckTokens(tokens);

        if (tokensToRemove.isEmpty()) return;
        AstUtils.removeNodesWithCleanup(root, tokensToRemove::contains);
    }

    private Set<ClangToken> findTypeInitCheckTokens(List<ClangToken> tokens) {
        Set<ClangToken> result = new LinkedHashSet<>();

        for (int i = 0; i < tokens.size(); i++) {
            if (!isIfKeyword(tokens.get(i))) continue;

            int patternEnd = new PatternMatcher(tokens, i).match();

            if (patternEnd != -1) {
                for (int j = i; j <= patternEnd; j++) {
                    result.add(tokens.get(j));
                }
                i = patternEnd;
            }
        }

        return result;
    }

    private boolean isIfKeyword(ClangToken token) {
        return "if".equals(token.getText());
    }

    // =========================================================================
    // Pattern Matcher (FSM)
    // =========================================================================

    private enum State {
        EXPECT_CONDITION_START,  // Expecting '(' after 'if'
        PARSE_CONDITION,         // Looking for DAT_* == '\0'
        EXPECT_BODY_START,       // Expecting '{' after condition
        PARSE_BODY,              // Looking for &*_TypeInfo
        SUCCESS,
        FAILURE
    }

    private static class PatternMatcher {
        private final List<ClangToken> tokens;
        private final int startIndex;

        private State state = State.EXPECT_CONDITION_START;
        private int pos;
        private int depth = 0;

        private boolean foundDatVariable = false;
        private boolean foundNullComparison = false;
        private boolean foundTypeInfoReference = false;

        PatternMatcher(List<ClangToken> tokens, int ifIndex) {
            this.tokens = tokens;
            this.startIndex = ifIndex;
            this.pos = ifIndex + 1;
        }

        /**
         * Attempts to match the type initialization check pattern.
         * @return index of last matched token, or -1 if no match
         */
        int match() {
            while (pos < tokens.size() && isRunning()) {
                process(tokens.get(pos));
                pos++;
            }
            return state == State.SUCCESS ? pos - 1 : -1;
        }

        private boolean isRunning() {
            return state != State.SUCCESS && state != State.FAILURE;
        }

        private void process(ClangToken token) {
            if (isWhitespace(token)) return;

            String text = token.getText();

            switch (state) {
                case EXPECT_CONDITION_START -> {
                    if ("(".equals(text)) {
                        depth = 1;
                        state = State.PARSE_CONDITION;
                    } else {
                        state = State.FAILURE;
                    }
                }

                case PARSE_CONDITION -> {
                    if ("(".equals(text)) {
                        depth++;
                    } else if (")".equals(text)) {
                        depth--;
                        if (depth == 0) {
                            state = isValidCondition()
                                ? State.EXPECT_BODY_START
                                : State.FAILURE;
                        }
                    } else if (isDatVariable(text)) {
                        foundDatVariable = true;
                    } else if (isNullLiteral(text)) {
                        foundNullComparison = true;
                    }
                }

                case EXPECT_BODY_START -> {
                    if ("{".equals(text)) {
                        depth = 1;
                        state = State.PARSE_BODY;
                    } else {
                        state = State.FAILURE;
                    }
                }

                case PARSE_BODY -> {
                    if ("{".equals(text)) {
                        depth++;
                    } else if ("}".equals(text)) {
                        depth--;
                        if (depth == 0) {
                            state = foundTypeInfoReference
                                ? State.SUCCESS
                                : State.FAILURE;
                        }
                    } else if (isTypeInfoReference(text)) {
                        foundTypeInfoReference = true;
                    }
                }

                default -> state = State.FAILURE;
            }
        }

        private boolean isValidCondition() {
            return foundDatVariable && foundNullComparison;
        }

        private boolean isDatVariable(String text) {
            return text != null && text.startsWith(DAT_PREFIX);
        }

        private boolean isNullLiteral(String text) {
            return "'\\0'".equals(text)
                || "0".equals(text)
                || "NULL".equals(text)
                || "nullptr".equals(text);
        }

        private boolean isTypeInfoReference(String text) {
            return text != null && text.endsWith(TYPE_INFO_SUFFIX);
        }

        private boolean isWhitespace(ClangToken token) {
            String text = token.getText();
            return text == null || text.isBlank();
        }
    }
}