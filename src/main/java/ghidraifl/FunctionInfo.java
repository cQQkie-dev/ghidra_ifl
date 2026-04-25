package ghidraifl;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;

public class FunctionInfo {

    private final Program program;
    private final Function function;
    private final Address entry;
    private final Address end;

    private boolean isImport;
    private String typeString;
    private String argsString;
    private int argsNum;

    private final List<RefEntry> refsTo = new ArrayList<>();    // callers
    private final List<RefEntry> refsFrom = new ArrayList<>();  // callees
    private int totalRefs;

    public FunctionInfo(Program program, Function function) {
        this.program = program;
        this.function = function;
        this.entry = function.getEntryPoint();
        this.end = function.getBody().getMaxAddress();
    }

    // --- getters ---

    public Program getProgram() {
        return program;
    }

    public Function getFunction() {
        return function;
    }

    public Address getEntry() {
        return entry;
    }

    public Address getEnd() {
        return end;
    }

    public boolean isImport() {
        return isImport;
    }

    public void setImport(boolean anImport) {
        isImport = anImport;
    }

    public String getTypeString() {
        return typeString;
    }

    public void setTypeString(String typeString) {
        this.typeString = typeString;
    }

    public String getArgsString() {
        return argsString;
    }

    public void setArgsString(String argsString) {
        this.argsString = argsString;
    }

    public int getArgsNum() {
        return argsNum;
    }

    public void setArgsNum(int argsNum) {
        this.argsNum = argsNum;
    }

    public List<RefEntry> getRefsTo() {
        return refsTo;
    }

    public List<RefEntry> getRefsFrom() {
        return refsFrom;
    }

    public int getTotalRefs() {
        return totalRefs;
    }

    public void setTotalRefs(int totalRefs) {
        this.totalRefs = totalRefs;
    }

    public boolean contains(Address addr) {
        return addr.compareTo(entry) >= 0 && addr.compareTo(end) <= 0;
    }
}