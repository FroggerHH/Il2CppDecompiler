package il2cppdecompiler.codeprocessing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CodeSanitizer {

    public String sanitizeForCs(String cCode) {
        return sanitizeForCs(cCode, true);
    }

    public String sanitizeForCs(String cCode, boolean includeLossyChanges) {
        int bodyIdx = cCode.indexOf("{");
        if (bodyIdx == -1)
            return cCode; // Fallback

        String header = cCode.substring(0, bodyIdx - 2);
        String body = cCode.substring(bodyIdx);
        String[] bodyParts = body.split("\\n\\s*\\n", 2);

        // Handle case where split might not work as expected
        String varDeclarations = bodyParts.length > 0 ? bodyParts[0] : "";
        String code = bodyParts.length > 1 ? bodyParts[1] : body;

        if (includeLossyChanges) {
            header = header.replaceFirst(",?[\\s\\n]*MethodInfo [^)]+", "");
        }

        code = code.replaceFirst("^\\s*if \\(DAT_(?:.|\\n)+?}", "");

        if (includeLossyChanges) {
            Pattern nullCheckPattern = Pattern.compile("^(\\s*)if \\(\\w+ != NULL\\) \\{$");
            List<String> lines = new ArrayList<>(Arrays.asList(code.split("\\n")));
            for (int i = 0; i < lines.size(); i++) {
                Matcher matcher = nullCheckPattern.matcher(lines.get(i));
                if (matcher.find()) {
                    lines.remove(i);
                    String indentation = matcher.group(1);
                    for (int j = i; j < lines.size(); j++) {
                        String line = lines.get(j);
                        String newLine = line.startsWith(indentation) ? line.substring(2) : line;
                        lines.set(j, newLine);
                        if (line.equals(indentation + "}")) {
                            lines.remove(j);
                            break;
                        }
                    }
                }
            }
            code = String.join("\n", lines);

            code = code.replaceAll("\\bNULL\\b", "null");
            code = code.replaceAll("\\b__this\\b", "this");
            code = code.replaceAll("\\((\\w+)->(?:fields|klass->vtable)\\)", "$1");
        }

        code = code.replaceAll("\\.(?:fields|field0_0x0)\\.", ".");

        if (includeLossyChanges) {
            code = code.replaceAll(",?[\\s\\n]*\\(MethodInfo \\*\\)0x0(?=[\\s\\n]*\\))", "");
            code = code.replaceAll(
                "\\(\\*([^;]+?)\\._\\d+_(\\w+)\\.methodPtr\\b\\)[\\s\\n]*\\([^,)]*,?[\\s\\n]*",
                "$1.$2(");
            code = code.replaceAll("(\\W)\\(\\w+\\W*\\)", "$1");
        }

        code = code.replaceAll("\\b_(\\w+)_k__BackingField\\b", "$1");

        if (includeLossyChanges) {
            code = code.replaceAll(
                "(\\w+)[\\s\\n]*<\\w+>[\\s\\n]*\\(([^)]*),[\\s\\n]*Method_\\w+[\\s\\n]*<(\\w+)>[\\s\\n]*__[\\s\\n]*\\)",
                "$1<$3>($2)");

            List<String> vars = new ArrayList<>();
            Pattern varNamePattern = Pattern.compile("\\w+(?=;)");
            for (String line : varDeclarations.split("\n")) {
                Matcher matcher = varNamePattern.matcher(line);
                if (matcher.find()) {
                    vars.add(matcher.group());
                }
            }
            for (String varName : vars) {
                Pattern assignmentPattern =
                    Pattern.compile("\\n\\s*" + varName + "\\s*=[\\s\\n]*((?:.|\\n)+?);");
                List<MatchResult> assignments = assignmentPattern.matcher(code).results().toList();
                if (assignments.size() == 1) {
                    MatchResult assignment = assignments.get(0);
                    Pattern usagePattern = Pattern.compile("[^.]\\b" + varName + "\\b");
                    List<MatchResult> usages = usagePattern.matcher(code).results().toList();
                    if (usages.size() == 2) {
                        MatchResult usage = usages.get(1);
                        code = code.substring(0, assignment.start()) +
                            code.substring(assignment.end(), usage.start() + 1) +
                            assignment.group(1) +
                            code.substring(usage.end());
                    }
                }
            }
        }

        return header + " {\n" + code;
    }
}