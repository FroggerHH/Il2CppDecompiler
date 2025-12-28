package il2cppdecompiler.codeprocessing.sanitizer.processors.ast;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import il2cppdecompiler.codeprocessing.sanitizer.CodeContext;
import il2cppdecompiler.codeprocessing.sanitizer.ICodeProcessor;
import il2cppdecompiler.codeprocessing.sanitizer.util.AstUtils;
import il2cppdecompiler.util.Logger;

// if ((Albion_Common_Math_Vector2_TypeInfo->_2).cctor_finished == 0) {
//   il2cpp_runtime_class_init();
// }

public class StaticConstructorCheckRemover implements ICodeProcessor {

    private static final String CCTOR_FINISHED = "cctor_finished";
    private static final String RUNTIME_CLASS_INIT = "il2cpp_runtime_class_init";

    public StaticConstructorCheckRemover(Logger logger) {}

    @Override
    public void process(CodeContext context) {
        ClangTokenGroup root = context.getAstRoot();
        if (root == null) return;
        removeConstructorChecks(root);
    }

    @Override public int getPriority() { return 30; }

    private void removeConstructorChecks(ClangTokenGroup root) {
        if (root == null) return;

        List<ClangToken> tokens = AstUtils.flattenChildrenToList(root);
        if (tokens.isEmpty()) return;

        Set<ClangToken> tokensToRemove = findConstructorCheckTokens(tokens);

        if (tokensToRemove.isEmpty()) return;
        AstUtils.removeNodesWithCleanup(root, tokensToRemove::contains);
    }

    private Set<ClangToken> findConstructorCheckTokens(List<ClangToken> tokens) {
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
        PARSE_CONDITION,         // Inside condition, looking for cctor_finished
        EXPECT_BODY_START,       // Expecting '{' after condition
        PARSE_BODY,              // Inside body, looking for il2cpp_runtime_class_init
        SUCCESS,
        FAILURE
    }

    private static class PatternMatcher {
        private final List<ClangToken> tokens;
        private final int startIndex;

        private State state = State.EXPECT_CONDITION_START;
        private int pos;
        private int depth = 0;

        private boolean foundCctorFinished = false;
        private boolean foundRuntimeInit = false;

        PatternMatcher(List<ClangToken> tokens, int ifIndex) {
            this.tokens = tokens;
            this.startIndex = ifIndex;
            this.pos = ifIndex + 1; // Skip 'if' keyword
        }

        /**
         * Attempts to match the constructor check pattern.
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
                            state = foundCctorFinished
                                ? State.EXPECT_BODY_START
                                : State.FAILURE;
                        }
                    } else if (isCctorFinished(token)) {
                        foundCctorFinished = true;
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
                            state = foundRuntimeInit
                                ? State.SUCCESS
                                : State.FAILURE;
                        }
                    } else if (isRuntimeClassInit(token)) {
                        foundRuntimeInit = true;
                    }
                }

                default -> state = State.FAILURE;
            }
        }

        private boolean isCctorFinished(ClangToken token) {
            if (token instanceof ClangFieldToken field) {
                return CCTOR_FINISHED.equals(field.getText());
            }
            return CCTOR_FINISHED.equals(token.getText());
        }

        private boolean isRuntimeClassInit(ClangToken token) {
            return RUNTIME_CLASS_INIT.equals(token.getText());
        }

        private boolean isWhitespace(ClangToken token) {
            String text = token.getText();
            return text == null || text.isBlank();
        }
    }
}