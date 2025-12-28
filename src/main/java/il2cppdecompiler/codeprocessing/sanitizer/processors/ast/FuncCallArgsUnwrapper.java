package il2cppdecompiler.codeprocessing.sanitizer.processors.ast;

import ghidra.app.decompiler.*;
import il2cppdecompiler.codeprocessing.sanitizer.CodeContext;
import il2cppdecompiler.codeprocessing.sanitizer.ICodeProcessor;
import il2cppdecompiler.codeprocessing.sanitizer.util.AstUtils;
import il2cppdecompiler.util.Logger;

import java.util.List;
import java.util.ListIterator;

public class FuncCallArgsUnwrapper implements ICodeProcessor {
    public FuncCallArgsUnwrapper(Logger logger){}

    @Override
    public void process(CodeContext context) {
        if (context.getAstRoot() == null) return;
        unwrapRecursive(context.getAstRoot());
    }

    @Override
    public int getPriority() {
        return 10;
    }

    private void unwrapRecursive(ClangTokenGroup group) {
        List<ClangNode> tokens = AstUtils.getChildren(group);
        if (tokens.isEmpty()) return;

        ListIterator<ClangNode> it = tokens.listIterator();
        
        while (it.hasNext()) {
            ClangNode node = it.next();

            if (node instanceof ClangTokenGroup) {
                unwrapRecursive((ClangTokenGroup) node);
                continue;
            }

            if (node instanceof ClangFuncNameToken) {
                tryAttachOpeningParenthesis(it);
            }
        }
    }

    private void tryAttachOpeningParenthesis(ListIterator<ClangNode> it) {
        int stepsForward = 0;
        boolean success = false;

        while (it.hasNext()) {
            ClangNode nextNode = it.next();
            stepsForward++;

            if (nextNode instanceof ClangToken) {
                String text = ((ClangToken) nextNode).getText();

                if ("(".equals(text)) {
                    success = true;
                    break;
                }

                if (isWhitespaceOrNewline(text)) {
                    continue; 
                }

                break;
            } else {
                break;
            }
        }

        if (success) {
            
            if (it.hasPrevious()) it.previous(); 
            
            while (stepsForward > 1) { 
                if (it.hasPrevious()) {
                    it.previous(); 
                    it.remove();  
                    stepsForward--;
                } else {
                    break; 
                }
            }
        } else {
            while (stepsForward > 0) {
                if (it.hasPrevious()) it.previous();
                stepsForward--;
            }
        }
    }

    private boolean isWhitespaceOrNewline(String text) {
        if (text == null) return false;
        return text.trim().isEmpty();
    }
}