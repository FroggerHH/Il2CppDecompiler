package il2cppdecompiler.codeprocessing.sanitizer.processors.ast;

import ghidra.app.decompiler.ClangCommentToken;
import il2cppdecompiler.codeprocessing.sanitizer.CodeContext;
import il2cppdecompiler.codeprocessing.sanitizer.ICodeProcessor;
import il2cppdecompiler.codeprocessing.sanitizer.util.AstUtils;
import il2cppdecompiler.util.Logger;

public class CommentRemover implements ICodeProcessor {
    public CommentRemover(Logger logger){}

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