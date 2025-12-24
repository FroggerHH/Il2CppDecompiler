package il2cppdecompiler.codeprocessing.sanitizer.processors.ast;

import ghidra.app.decompiler.ClangCommentToken;
import il2cppdecompiler.codeprocessing.sanitizer.AstUtils;
import il2cppdecompiler.codeprocessing.sanitizer.CodeContext;
import il2cppdecompiler.codeprocessing.sanitizer.ICodeProcessor;

public class CommentRemover implements ICodeProcessor {

    @Override
    public void process(CodeContext context) {
        if (context.getAstRoot() == null) return;

        AstUtils.removeNodesWithCleanup(context.getAstRoot(), node -> node instanceof ClangCommentToken);
    }

    @Override
    public int getPriority() {
        return 20;
    }
}