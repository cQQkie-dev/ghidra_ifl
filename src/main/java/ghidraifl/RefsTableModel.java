package ghidraifl;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import javax.swing.table.AbstractTableModel;
import java.util.Collections;
import java.util.List;

public class RefsTableModel extends AbstractTableModel {

    public enum Mode {
        REFS_TO,
        REFS_FROM
    }

    private final Mode mode;

    private Program program;
    private FunctionManager functionManager;
    private Listing listing;

    private List<RefEntry> rows = Collections.emptyList();

    private static final String[] COLUMN_NAMES = { "Foreign Val.", "From", "To" };

    public RefsTableModel(Mode mode) {
        this.mode = mode;
    }

    /**
     * Called from IFLProvider.setProgram to give us the current Program.
     */
    public void setProgram(Program program) {
        this.program = program;
        if (program != null) {
            this.functionManager = program.getFunctionManager();
            this.listing = program.getListing();
        }
        else {
            this.functionManager = null;
            this.listing = null;
        }
        rows = Collections.emptyList();
        fireTableDataChanged();
    }

    /**
     * Called when the selected FunctionInfo changes.
     */
    public void setFunction(FunctionInfo info) {
        if (info == null) {
            rows = Collections.emptyList();
        }
        else if (mode == Mode.REFS_TO) {
            rows = info.getRefsTo();
        }
        else {
            rows = info.getRefsFrom();
        }
        fireTableDataChanged();
    }

    public RefEntry getRow(int rowIndex) {
        return rows.get(rowIndex);
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= rows.size()) {
            return "";
        }

        RefEntry ref = rows.get(rowIndex);

        if (mode == Mode.REFS_TO) {
            // REFS_TO: from = caller; destEntry = this function's entry
            Address from = ref.getFrom();
            Address to = ref.getDestEntry();

            if (columnIndex == 0) {
                // Foreign Val. = caller function name or [addr]: disasm or raw address
                if (program == null || functionManager == null || listing == null || from == null) {
                    return "";
                }
                Function caller = functionManager.getFunctionContaining(from);
                if (caller != null) {
                    return caller.getName();
                }
                Instruction instr = listing.getInstructionAt(from);
                if (instr != null) {
                    return String.format("[0x%X]: %s", from.getOffset(), instr.toString());
                }
                return String.format("0x%X", from.getOffset());
            }
            else if (columnIndex == 1) {
                return from != null ? String.format("0x%X", from.getOffset()) : "";
            }
            else {
                return to != null ? String.format("0x%X", to.getOffset()) : "";
            }
        }
        else {
            // REFS_FROM: from = call site; destEntry = callee entry or null; destName = callee name
            Address from = ref.getFrom();
            Address destEntry = ref.getDestEntry();
            boolean external = ref.isDestExternal();

            if (columnIndex == 0) {
                // Foreign Val. for REFS_FROM:
                //  - internal callee: get current function name from Program
                //  - external callee: use stored destName
                if (!external && destEntry != null && functionManager != null) {
                    Function destFunc = functionManager.getFunctionAt(destEntry);
                    if (destFunc != null) {
                        return destFunc.getName();
                    }
                }
                return ref.getDestName();
            }
            else if (columnIndex == 1) {
                return from != null ? String.format("0x%X", from.getOffset()) : "";
            }
            else {
                if (external || destEntry == null) {
                    return "<external>";
                }
                return String.format("0x%X", destEntry.getOffset());
            }
        }
    }
}