package cppclassanalyzer.utils;

import ghidra.program.model.lang.LanguageID;

public class LanguageIdHandler {

    private final String[] id;

    public LanguageIdHandler(LanguageID id) {
        this.id = id.getIdAsString().split(":");
    }

    public String getProcessor() {
        return id[0];
    }

    public String getEndianess() {
        return id[1];
    }

    public String getAddressSize() {
        return id[2];
    }

    public String getVariant() {
        return id[3];
    }
}