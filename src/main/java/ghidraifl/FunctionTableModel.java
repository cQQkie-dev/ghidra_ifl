package ghidraifl;

import ghidra.program.model.listing.Function;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class FunctionTableModel extends AbstractTableModel {

    public static final int COL_START       = 0;
    public static final int COL_END         = 1;
    public static final int COL_NAME        = 2;
    public static final int COL_TYPE        = 3;
    public static final int COL_ARGS        = 4;
    public static final int COL_REFS_TO     = 5;
    public static final int COL_REFS_FROM   = 6;
    public static final int COL_TOTAL_REFS  = 7;
    public static final int COL_IMPORT      = 8;

    private final String[] columnNames = {
        "Start",
        "End",
        "Name",
        "Type",
        "Args",
        "Is referred by",
        "Refers to",
        "Total refs",
        "Imported?"
    };

    private final List<FunctionInfo> rows;

    public FunctionTableModel(List<FunctionInfo> rows) {
        this.rows = rows;
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == COL_REFS_TO || columnIndex == COL_REFS_FROM || columnIndex == COL_TOTAL_REFS) {
            return Integer.class;
        }
        return String.class;
    }

    public FunctionInfo getRow(int rowIndex) {
        return rows.get(rowIndex);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        FunctionInfo info = rows.get(rowIndex);
        Function f = info.getFunction();

        switch (columnIndex) {
            case COL_START:
                return String.format("0x%X", info.getEntry().getOffset());
            case COL_END:
                return String.format("0x%X", info.getEnd().getOffset());
            case COL_NAME:
                // always read current name (supports undo/redo)
                String currentName = f.getName();
                return currentName;
            case COL_TYPE:
                return info.getTypeString();
            case COL_ARGS:
                return info.getArgsString();
            case COL_REFS_TO:
                return info.getRefsTo().size();
            case COL_REFS_FROM:
                return info.getRefsFrom().size();
            case COL_TOTAL_REFS:
                return info.getTotalRefs();
            case COL_IMPORT:
                return info.isImport() ? "+" : "-";
            default:
                return "";
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false; // rename via context menu / action
    }
}