package il2cppdecompiler.model;

import java.util.HashSet;
import java.util.Map;

public class DecompiledType {
    public String namespace;
    public String category;
    public String name;
    public String fullName;
    public String cName;
    public String heading;
    public Map<String, String> items;
    public HashSet<String> properties;
    public HashSet<String> methods;
    public String rawStr;

    // Можно добавить геттеры/сеттеры или оставить публичными полями для DTO
}