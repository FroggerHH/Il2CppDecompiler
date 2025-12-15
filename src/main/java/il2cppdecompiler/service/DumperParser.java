package il2cppdecompiler.service;

import il2cppdecompiler.model.DecompiledType;
import il2cppdecompiler.util.Trie;
import il2cppdecompiler.api.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Pattern;

public class DumperParser {
    private final static Pattern DUMP_CS_PATTERN = Pattern.compile(
        "(// Namespace: ([^\\n]*)\\n" +
            "[^{]*?([^\\s\\n]+) ([^\\s\\n]+)(?: : [^\\s\\n]+)?(?: //[^\\n]*\\n)?)" +
            " ?(\\{\\}|\\{.*?\\n\\})",
        Pattern.DOTALL);
    private final static Pattern FIELD_PATTERN =
        Pattern.compile("[^;]+?([^\\s;]+)\\s*(?:=[^;]+)?;", Pattern.DOTALL);
    private final static Pattern PROP_BACKING_FIELD_PATTERN =
        Pattern.compile("<(\\S+?)>k__BackingField");
    private final static Pattern PROPERTY_PATTERN =
        Pattern.compile("[^{}]+?([^\\s{]+)\\s*\\{[^}]*\\}", Pattern.DOTALL);
    private final static Pattern METHOD_NAME_PATTERN =
        Pattern.compile("[^\\s\\(\\n]+(?=\\s*\\()", Pattern.DOTALL);
    private final static String COMMENT_PATTERN = "\\s*//.*|/\\*.*?\\*/";

    private final ProjectWorkspace workspace;
    private final String dumperOutputDir;
    private final Logger logger;
    
    // Результаты парсинга
    public final Map<String, DecompiledType> typesByCName = new HashMap<>();
    public final Trie typeKeys = new Trie();
    private final Set<String> headerTokens = new HashSet<>();

    public DumperParser(ProjectWorkspace workspace, String dumperOutputDir, Logger logger) throws IOException {
        this.workspace = workspace;
        this.dumperOutputDir = dumperOutputDir;
        this.logger = logger;
    }

    public void parse() throws IOException {
        parseHeader();
        parseDumpCs();
    }

    private String readOutputFile(String filename) throws IOException {
        // Кэшируем файлы в папку проекта для ускорения доступа
        var file = workspace.getProjectFile("DumperOutput/" + filename);
        if (!file.exists()) {
            file.getParentFile().mkdirs();
            Path sourcePath = Path.of(dumperOutputDir, filename);
            if (!Files.exists(sourcePath)) {
                throw new IOException("Il2CppDumper file not found: " + sourcePath);
            }
            Files.copy(sourcePath, file.toPath());
        }
        return Files.readString(file.toPath());
    }

    private void parseHeader() throws IOException {
        var content = readOutputFile("il2cpp.h");
        var matcher = Pattern.compile("\\w+").matcher(content);
        while (matcher.find()) {
            headerTokens.add(matcher.group(0));
        }
    }

    private void parseDumpCs() throws IOException {
        var content = readOutputFile("dump.cs");
        var matcher = DUMP_CS_PATTERN.matcher(content);

        while (matcher.find()) {
            var type = new DecompiledType();
            type.namespace = matcher.group(2);
            type.category = matcher.group(3);
            type.name = matcher.group(4);
            type.fullName = type.namespace.length() > 0 ? type.namespace + "." + type.name : type.name;
            type.cName = headerFixName(type.fullName);
            type.heading = matcher.group(1).replaceAll(COMMENT_PATTERN, "");
            type.items = new HashMap<>();
            type.properties = new HashSet<>();
            type.methods = new HashSet<>();
            type.rawStr = matcher.group(0);

            var sections = matcher.group(5).split("\\s*// (?=Fields|Properties|Methods\\n)");
            parseProperties(getSection(sections, "Properties"), type);
            parseFields(getSection(sections, "Fields"), type);
            parseMethods(getSection(sections, "Methods"), type);

            typesByCName.put(type.cName, type);
            typeKeys.insert(type.cName);
        }
    }

    // Helper methods
    private static String getSection(String[] sections, String name) {
        for (var section : sections) {
            if (section.startsWith(name)) {
                return section.substring(name.length() + 1);
            }
        }
        return null;
    }

    private void parseProperties(String raw, DecompiledType type) {
        if (raw == null) return;
        var matcher = PROPERTY_PATTERN.matcher(raw);
        while (matcher.find()) {
            var contents = matcher.group(0).replaceAll(COMMENT_PATTERN, "");
            var name = matcher.group(1);
            type.items.put(headerFixName(name), cleanItem(contents));
            type.properties.add(name);
        }
    }

    private void parseFields(String raw, DecompiledType type) {
        if (raw == null) return;
        var matcher = FIELD_PATTERN.matcher(raw);
        while (matcher.find()) {
            var contents = matcher.group(0).replaceAll(COMMENT_PATTERN, "");
            var name = matcher.group(1);
            var backingFieldMatcher = PROP_BACKING_FIELD_PATTERN.matcher(name);
            if (backingFieldMatcher.find() && type.properties.contains(backingFieldMatcher.group(1))) {
                continue;
            }
            type.items.put(headerFixName(name), cleanItem(contents));
        }
    }

    private static final Map<String, String> operatorsByName = Map.ofEntries(
        Map.entry("Implicit", "implicit"), Map.entry("Explicit", "explicit"),
        Map.entry("Addition", "+"), Map.entry("Subtraction", "-"),
        Map.entry("Multiply", "*"), Map.entry("Division", "/"),
        Map.entry("Modulus", "%"), Map.entry("Equality", "=="),
        Map.entry("Inequality", "!="), Map.entry("GreaterThan", ">"),
        Map.entry("LessThan", "<"), Map.entry("GreaterThanOrEqual", ">="),
        Map.entry("LessThanOrEqual", "<="), Map.entry("LeftShift", "<<"),
        Map.entry("RightShift", ">>"), Map.entry("Increment", "++"),
        Map.entry("Decrement", "--"), Map.entry("UnaryNegation", "-")
    );

    private void parseMethods(String raw, DecompiledType type) {
        if (raw == null) return;
        var methods = raw.split("\\}");
        for (var i = 0; i < methods.length - 1; i++) {
            var contents = (methods[i] + "}").replaceAll(COMMENT_PATTERN, "");
            var matcher = METHOD_NAME_PATTERN.matcher(contents);
            String name = null;
            while (matcher.find()) name = matcher.group(0);
            
            if (name == null) continue;
            type.methods.add(name);

            if (name.startsWith("get_") || name.startsWith("set_")) {
                if (type.properties.contains(name.substring(4))) continue;
            }

            if (name.startsWith("op_")) {
                var operatorName = name.substring(3);
                var operator = operatorsByName.get(operatorName);
                if (operator != null) {
                    contents = contents.replace(name, "operator " + operator);
                }
            }
            type.items.put(headerFixName(name), cleanItem(contents));
        }
    }

    private static final Set<String> C_KEYWORDS = new HashSet<>(Arrays.asList(
        "klass", "monitor", "register", "_cs", "auto", "friend", "template",
        "flat", "default", "_ds", "interrupt", "unsigned", "signed", "asm",
        "if", "case", "break", "continue", "do", "new", "_", "short", "union",
        "class", "namespace"));
    private static final Set<String> C_SPECIAL_KEYWORDS = new HashSet<>(Arrays.asList("inline", "near", "far"));

    private String headerFixName(String name) {
        var result = name;
        if (C_KEYWORDS.contains(result)) result = "_" + result;
        else if (C_SPECIAL_KEYWORDS.contains(result)) result = "_" + result + "_";

        if (Pattern.matches("^[0-9]", result)) return "_" + result;
        else return result.replaceAll("[^a-zA-Z0-9_]", "_");
    }

    private static String cleanItem(String contents) {
        return ("\n" + contents.strip()).replaceAll("\\n\\s*", "\n  ").substring(1) + "\n";
    }
}