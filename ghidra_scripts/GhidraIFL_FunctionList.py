# Ghidra-IFL: Interactive Functions List UI
#
# Features:
# - Top:  JTable of all functions, sortable, filterable, colored.
#   * Filter panel:
#       - Column: Start/End/Name/Type/Args/Is referred by/Refers to/Total refs/Imported?
#       - Mode: contains / matches (regex)
#       - Text: case-insensitive; press Enter to apply.
#   * Color controls:
#       - "Color by": Total refs / Is referred by / Refers to
#       - "Thresh": numeric threshold; empty = auto
#   * Colors (top table):
#       - Imported funcs: import_bg.
#       - High metric (based on selected "Color by") funcs: gradient from low_ref_bg to high_ref_bg.
#
# - Bottom: label + tabs for "Is referred by" and "Refers to".
# - Double-click:
#   * Top row -> navigate to function entry.
#   * "Is referred by" row -> go to caller (from address).
#   * "Refers to" row:
#       - internal callee -> go to callee entry
#       - external callee -> go to call site.
# - Right-click on top table row:
#   * Rename...
#   * Keep selected in current view
#   * Remove selected from current view
#   * Remove current view from full table
#
#@author Matthias Koch
#@category IFL
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

from ghidra.app.services import GoToService
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.listing import CommentType
from ghidra.program.model.symbol import SourceType

from javax.swing import (
    JButton, JFrame, JComponent, JTable, JScrollPane,
    SwingUtilities, JPanel, JLabel, JTabbedPane,
    JSplitPane, JComboBox, JTextField, RowFilter,
    JPopupMenu, JMenuItem, JOptionPane, JFileChooser,
    KeyStroke
)
from javax.swing.table import TableModel, TableRowSorter, TableCellRenderer, DefaultTableCellRenderer
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, Color
from java.awt.event import MouseListener, ActionListener, KeyEvent, InputEvent, KeyListener
from java.lang import Object, Integer, String
from java.util.regex import Pattern

from generic.theme import GIcon  # for function/external icons

import jpype
from java.io import File, FileWriter, BufferedWriter, PrintWriter
from collections import deque

# ----------------------------------------------------------------------
# Core data model (mapper)
# ----------------------------------------------------------------------

class FunctionInfo(object):
    def __init__(self, func, program):
        self.func = func
        self.program = program
        self.entry = func.getEntryPoint()
        self.start = self.entry.getOffset()

        body = func.getBody()
        if body is not None and not body.isEmpty():
            self.end_addr = body.getMaxAddress()
            self.end = self.end_addr.getOffset()
        else:
            self.end_addr = self.entry
            self.end = self.start

        self.name = func.getName()
        self.is_import = classify_import(func)

        self.type_str, self.args_str, self.args_num = get_function_type_info(func)

        self.refs_to = []    # list[(from_off, this_func_start_off)]
        # refs_from entries: (from_off, dest_off, dest_name, dest_is_external)
        self.refs_from = []
        self.total_refs = 0  # filled after mapping

    def contains(self, addr_off):
        return self.start <= addr_off <= self.end


def classify_import(func):
    try:
        if func.isExternal():
            return True
        if func.isThunk():
            try:
                thunked = func.getThunkedFunction(True)
            except TypeError:
                thunked = func.getThunkedFunction()
            if thunked is not None and thunked.isExternal():
                return True
    except Exception:
        pass
    return False


def get_function_type_info(func):
    try:
        sig = func.getSignature()
    except Exception:
        return ("?", "()", 0)

    try:
        ret_type = sig.getReturnType()
        ret_str = ret_type.getDisplayName() if ret_type is not None else "?"
    except Exception:
        ret_str = "?"

    try:
        cc_name = sig.getCallingConventionName() or ""
    except Exception:
        cc_name = ""

    if cc_name:
        type_str = "%s %s" % (ret_str, cc_name)
    else:
        type_str = ret_str

    args_num = 0
    arg_parts = []
    try:
        params = sig.getArguments()
        args_num = len(params)
        if args_num == 0:
            args_str = "(void)"
        else:
            for p in params:
                try:
                    p_type = p.getDataType()
                    p_type_str = p_type.getDisplayName() if p_type is not None else "?"
                except Exception:
                    p_type_str = "?"
                try:
                    p_name = p.getName()
                except Exception:
                    p_name = ""
                if not p_name:
                    arg_parts.append(p_type_str)
                else:
                    arg_parts.append("%s %s" % (p_type_str, p_name))
            args_str = "(" + ", ".join(arg_parts) + ")"
    except Exception:
        args_str = "()"
        args_num = 0

    return (type_str, args_str, args_num)


def build_ifl_function_map(program):
    fm = program.getFunctionManager()
    ref_mgr = program.getReferenceManager()
    listing = program.getListing()

    func_infos = []
    func_by_start = {}

    for func in fm.getFunctions(True):
        info = FunctionInfo(func, program)
        func_infos.append(info)
        func_by_start[info.start] = info

    # refs_to
    for info in func_infos:
        entry_addr = info.entry
        if entry_addr is None:
            continue
        for ref in ref_mgr.getReferencesTo(entry_addr):
            from_a = ref.getFromAddress()
            if listing.getInstructionAt(from_a) is None:
                continue
            from_off = from_a.getOffset()
            info.refs_to.append((from_off, info.start))

    # refs_from
    for info in func_infos:
        if info.func.isExternal():
            continue
        func = info.func
        body = func.getBody()
        if body is None or body.isEmpty():
            continue
        instr_iter = listing.getInstructions(body, True)
        for instr in instr_iter:
            from_addr = instr.getAddress()
            from_off = from_addr.getOffset()
            for ref in ref_mgr.getReferencesFrom(from_addr):
                to_addr = ref.getToAddress()
                if to_addr is None:
                    continue
                to_off_raw = to_addr.getOffset()
                if info.contains(to_off_raw):
                    continue
                dest_func = fm.getFunctionContaining(to_addr)
                if dest_func is None:
                    continue
                dest_name = dest_func.getName()
                dest_is_external = dest_func.isExternal()
                if dest_is_external:
                    dest_off = -1
                else:
                    dest_off = dest_func.getEntryPoint().getOffset()
                info.refs_from.append((from_off, dest_off, dest_name, dest_is_external))

    # total_refs
    for info in func_infos:
        info.total_refs = len(info.refs_to) + len(info.refs_from)

    return func_infos, func_by_start

# ----------------------------------------------------------------------
# TableModel for main functions table (via JProxy)
# ----------------------------------------------------------------------

class PyFunctionTableModel(object):
    COL_START = 0
    COL_END = 1
    COL_NAME = 2
    COL_TYPE = 3
    COL_ARGS = 4
    COL_REFS_TO = 5
    COL_REFS_FROM = 6
    COL_TOTAL_REFS = 7
    COL_IMPORT = 8

    def __init__(self, func_infos, program):
        self.func_infos = func_infos
        self.program = program
        self.headers = [
            "Start",
            "End",
            "Name",
            "Type",
            "Args",
            "Is referred by",
            "Refers to",
            "Total refs",
            "Imported?",
        ]
        self.listeners = []

    def getRowCount(self):
        return len(self.func_infos)

    def getColumnCount(self):
        return len(self.headers)

    def getColumnName(self, columnIndex):
        return self.headers[columnIndex]

    def getColumnClass(self, columnIndex):
        if columnIndex in (self.COL_REFS_TO, self.COL_REFS_FROM, self.COL_TOTAL_REFS):
            return Integer
        elif columnIndex == self.COL_IMPORT:
            return String
        else:
            return String

    def isCellEditable(self, rowIndex, columnIndex):
        return False

    def getValueAt(self, rowIndex, columnIndex):
        info = self.func_infos[rowIndex]
        col = columnIndex
        if col == self.COL_START:
            return "0x%X" % info.start
        elif col == self.COL_END:
            return "0x%X" % info.end
        elif col == self.COL_NAME:
            # Always read from the Function to stay in sync with Undo/Redo
            try:
                current_name = info.func.getName()
                info.name = current_name  # keep cached field in sync, too
            except Exception:
                current_name = info.name
            return current_name
            
        elif col == self.COL_TYPE:
            return info.type_str
        elif col == self.COL_ARGS:
            return info.args_str
        elif col == self.COL_REFS_TO:
            return len(info.refs_to)
        elif col == self.COL_REFS_FROM:
            return len(info.refs_from)
        elif col == self.COL_TOTAL_REFS:
            return info.total_refs
        elif col == self.COL_IMPORT:
            return "+" if info.is_import else "-"
        else:
            return ""

    def setValueAt(self, aValue, rowIndex, columnIndex):
        return

    def addTableModelListener(self, l):
        self.listeners.append(l)

    def removeTableModelListener(self, l):
        if l in self.listeners:
            self.listeners.remove(l)

# ----------------------------------------------------------------------
# TableModel for refs tables (via JProxy)
# ----------------------------------------------------------------------

class PyRefsTableModel(object):
    def __init__(self, program, mode):
        self.program = program
        self.fm = program.getFunctionManager()
        self.listing = program.getListing()
        self.mode = mode  # "to" or "from"
        self.current_func = None
        self.rows = []
        self.headers = ["Foreign Val.", "From", "To"]
        self.listeners = []

    def setCurrentFunction(self, func_info):
        self.current_func = func_info
        if func_info is None:
            self.rows = []
        else:
            if self.mode == "to":
                self.rows = func_info.refs_to
            else:
                self.rows = func_info.refs_from

    def getRowCount(self):
        return len(self.rows)

    def getColumnCount(self):
        return len(self.headers)

    def getColumnName(self, columnIndex):
        return self.headers[columnIndex]

    def getColumnClass(self, columnIndex):
        return String

    def isCellEditable(self, rowIndex, columnIndex):
        return False

    def getValueAt(self, rowIndex, columnIndex):
        if rowIndex < 0 or rowIndex >= len(self.rows):
            return ""

        if self.mode == "to":
            from_off, to_off = self.rows[rowIndex]
            if columnIndex == 0:
                addr = toAddr(from_off)
                if addr is None:
                    return ""
                func = self.fm.getFunctionContaining(addr)
                if func is not None:
                    return func.getName()
                instr = self.listing.getInstructionAt(addr)
                if instr is not None:
                    return "[0x%X]: %s" % (addr.getOffset(), instr.toString())
                return "0x%X" % addr.getOffset()
            elif columnIndex == 1:
                return "0x%X" % from_off
            elif columnIndex == 2:
                return "0x%X" % to_off
            return ""
        else:
            from_off, dest_off, dest_name, dest_is_external = self.rows[rowIndex]
            if columnIndex == 0:
                return dest_name
            elif columnIndex == 1:
                return "0x%X" % from_off
            elif columnIndex == 2:
                if dest_is_external or dest_off < 0:
                    return "<external>"
                return "0x%X" % dest_off
            return ""

    def setValueAt(self, aValue, rowIndex, columnIndex):
        return

    def addTableModelListener(self, l):
        self.listeners.append(l)

    def removeTableModelListener(self, l):
        if l in self.listeners:
            self.listeners.remove(l)

# ----------------------------------------------------------------------
# Color configuration (mode + threshold)
# ----------------------------------------------------------------------

class ColorConfig(object):
    MODE_TOTAL = "total"
    MODE_REFS_TO = "refs_to"
    MODE_REFS_FROM = "refs_from"

    def __init__(self, func_infos):
        self.func_infos = func_infos
        self.mode = self.MODE_TOTAL
        self.auto_threshold = True
        self.manual_threshold = 0

        self.max_refs_to = max((len(fi.refs_to) for fi in func_infos), default=0)
        self.max_refs_from = max((len(fi.refs_from) for fi in func_infos), default=0)
        self.max_total = max((fi.total_refs for fi in func_infos), default=0)

    def get_metric(self, info):
        if self.mode == self.MODE_REFS_TO:
            return len(info.refs_to)
        elif self.mode == self.MODE_REFS_FROM:
            return len(info.refs_from)
        else:
            return info.total_refs

    def get_max_for_mode(self):
        if self.mode == self.MODE_REFS_TO:
            return self.max_refs_to
        elif self.mode == self.MODE_REFS_FROM:
            return self.max_refs_from
        else:
            return self.max_total

    def get_threshold(self):
        maxv = self.get_max_for_mode()
        if self.auto_threshold or self.manual_threshold <= 0:
            if maxv <= 0:
                return 0
            # auto: about top 80% (adjust divisor to taste)
            return max(1, maxv // 5)
        else:
            return self.manual_threshold

# ----------------------------------------------------------------------
# Cell renderer for top function table (coloring)
# ----------------------------------------------------------------------

from javax.swing import JLabel

class PyFunctionCellRenderer(object):
    """
    Custom cell renderer to color rows in the top function table.

    - Imported funcs: import_bg.
    - High metric funcs (based on ColorConfig.mode, using ColorConfig.get_metric):
      gradient between low_ref_bg and high_ref_bg, for metric >= threshold.

    Palette is chosen based on table background luminance (dark vs light theme)
    and a user-selected palette name: GREEN_RED, BLUE_ORANGE, PURPLE_CYAN.
    """

    def __init__(self, color_config):
        self.cfg = color_config
        self._palette_initialized = False
        self.palette = "GREEN_RED"  # default: Green-Red

        # Default palette (used until we initialize from table)
        self.import_bg = Color(90, 75, 40)
        self.low_ref_bg = Color(40, 70, 40)
        self.high_ref_bg = Color(150, 40, 40)

    def set_palette(self, palette_name):
        """
        Called when the palette dropdown changes.
        """
        if palette_name not in ("GREEN_RED", "BLUE_ORANGE", "PURPLE_CYAN"):
            palette_name = "GREEN_RED"
        self.palette = palette_name
        # Force re-initialization on the next paint
        self._palette_initialized = False

    def _init_palette_from_table(self, table):
        """
        Initialize palette based on table background luminance (dark vs light theme).
        Called lazily on first render or after set_palette().
        """
        if self._palette_initialized:
            return
        self._palette_initialized = True

        try:
            bg = table.getBackground()
            luminance = (
                0.2126 * bg.getRed() +
                0.7152 * bg.getGreen() +
                0.0722 * bg.getBlue()
            )
            is_dark = luminance < 128.0
        except Exception:
            # If anything goes wrong, keep defaults
            return

        # Adapted from Java FunctionCellRenderer.initColorsForPalette()
        if self.palette == "BLUE_ORANGE":
            if is_dark:
                self.import_bg = Color(180, 140, 90)
                self.low_ref_bg = Color(70, 80, 110)
                self.high_ref_bg = Color(200, 130, 60)
            else:
                self.import_bg = Color(255, 220, 180)
                self.low_ref_bg = Color(210, 220, 240)
                self.high_ref_bg = Color(255, 210, 160)
        elif self.palette == "PURPLE_CYAN":
            if is_dark:
                self.import_bg = Color(180, 120, 180)  # magenta-ish
                self.low_ref_bg = Color(90, 70, 140)   # dark purple
                self.high_ref_bg = Color(60, 150, 170) # teal/cyan
            else:
                self.import_bg = Color(240, 200, 240)
                self.low_ref_bg = Color(200, 180, 230)
                self.high_ref_bg = Color(180, 230, 240)
        else:  # GREEN_RED
            if is_dark:
                self.import_bg = Color(150, 120, 70)
                self.low_ref_bg = Color(60, 90, 60)
                self.high_ref_bg = Color(180, 80, 80)
            else:
                self.import_bg = Color(255, 230, 180)
                self.low_ref_bg = Color(220, 240, 220)
                self.high_ref_bg = Color(255, 210, 210)

    def _interp_color(self, c1, c2, t):
        t = max(0.0, min(1.0, float(t)))
        r = int(c1.getRed()   + t * (c2.getRed()   - c1.getRed()))
        g = int(c1.getGreen() + t * (c2.getGreen() - c1.getGreen()))
        b = int(c1.getBlue()  + t * (c2.getBlue()  - c1.getBlue()))
        return Color(r, g, b)

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        # Initialize palette once we have access to the table
        self._init_palette_from_table(table)

        label = JLabel()
        if value is not None:
            label.setText(str(value))

        if isSelected:
            label.setBackground(table.getSelectionBackground())
            label.setForeground(table.getSelectionForeground())
        else:
            bg = table.getBackground()
            fg = table.getForeground()

            model_row = table.convertRowIndexToModel(row)
            if 0 <= model_row < len(self.cfg.func_infos):
                info = self.cfg.func_infos[model_row]

                if info.is_import:
                    bg = self.import_bg
                else:
                    metric = self.cfg.get_metric(info)
                    maxv = self.cfg.get_max_for_mode()
                    thresh = self.cfg.get_threshold()

                    if maxv > 0 and metric >= thresh and metric > 0:
                        denom = float(maxv - thresh)
                        if denom <= 0:
                            t = 1.0
                        else:
                            t = float(metric - thresh) / denom
                        bg = self._interp_color(self.low_ref_bg, self.high_ref_bg, t)

            label.setBackground(bg)
            label.setForeground(fg)

        label.setOpaque(True)
        return label

# ----------------------------------------------------------------------
# Mouse/actions/selection/filter/autoResizeColumns
# ----------------------------------------------------------------------

class PyRenameActionListener(object):
    def __init__(self, info, program, table, parent):
        self.info = info
        self.program = program
        self.table = table
        self.parent = parent

    def actionPerformed(self, event):
        current_name = self.info.name
        new_name = JOptionPane.showInputDialog(
            self.parent,
            "New function name:",
            current_name
        )
        if new_name is None:
            return
        new_name = new_name.strip()
        if not new_name or new_name == current_name:
            return

        tx_id = self.program.startTransaction("Rename function")
        success = False
        try:
            self.info.func.setName(new_name, SourceType.USER_DEFINED)
            self.info.name = self.info.func.getName()
            success = True
        except Exception as e:
            print("Failed to rename function at 0x%X: %s" % (self.info.start, e))
        finally:
            self.program.endTransaction(tx_id, success)

        if success:
            self.table.revalidate()
            self.table.repaint()


class PyKeepSelectedActionListener(object):
    def __init__(self, table, func_infos, column_combo, mode_combo, filter_field, filter_controller):
        self.table = table
        self.func_infos = func_infos
        self.column_combo = column_combo
        self.mode_combo = mode_combo
        self.filter_field = filter_field
        self.filter_controller = filter_controller

    def actionPerformed(self, event):
        rows = self.table.getSelectedRows()
        if rows is None or len(rows) == 0:
            return

        names = []
        for r in rows:
            if r < 0:
                continue
            model_row = self.table.convertRowIndexToModel(r)
            if model_row < 0 or model_row >= len(self.func_infos):
                continue
            name = self.func_infos[model_row].name
            if name:
                names.append(name)

        if not names:
            return

        parts = [Pattern.quote(n) for n in names]
        pattern_body = "|".join(parts)
        regex = "^(?:%s)$" % pattern_body

        self.column_combo.setSelectedIndex(PyFunctionTableModel.COL_NAME)
        self.mode_combo.setSelectedItem("matches")
        self.filter_field.setText(regex)
        self.filter_controller.applyFilter()


class PyRemoveSelectedActionListener(object):
    def __init__(self, table, func_infos, column_combo, mode_combo, filter_field, filter_controller):
        self.table = table
        self.func_infos = func_infos
        self.column_combo = column_combo
        self.mode_combo = mode_combo
        self.filter_field = filter_field
        self.filter_controller = filter_controller

    def actionPerformed(self, event):
        row_count = self.table.getRowCount()
        if row_count <= 0:
            return

        visible_names = set()
        for view_row in range(row_count):
            model_row = self.table.convertRowIndexToModel(view_row)
            if model_row < 0 or model_row >= len(self.func_infos):
                continue
            name = self.func_infos[model_row].name
            if name:
                visible_names.add(name)
        if not visible_names:
            return

        selected_rows = self.table.getSelectedRows()
        selected_names = set()
        if selected_rows is not None:
            for r in selected_rows:
                if r < 0:
                    continue
                model_row = self.table.convertRowIndexToModel(r)
                if model_row < 0 or model_row >= len(self.func_infos):
                    continue
                name = self.func_infos[model_row].name
                if name:
                    selected_names.add(name)

        remaining_names = visible_names.difference(selected_names)
        if not remaining_names:
            return

        parts = [Pattern.quote(n) for n in remaining_names]
        pattern_body = "|".join(parts)
        regex = "^(?:%s)$" % pattern_body

        self.column_combo.setSelectedIndex(PyFunctionTableModel.COL_NAME)
        self.mode_combo.setSelectedItem("matches")
        self.filter_field.setText(regex)
        self.filter_controller.applyFilter()


class PyRemoveViewFromFullActionListener(object):
    """
    Remove the entire current view from the full table:
      new view = all functions - visible functions.
    """

    def __init__(self, table, func_infos, column_combo, mode_combo, filter_field, filter_controller):
        self.table = table
        self.func_infos = func_infos
        self.column_combo = column_combo
        self.mode_combo = mode_combo
        self.filter_field = filter_field
        self.filter_controller = filter_controller

    def actionPerformed(self, event):
        # All names (full set)
        all_names = set()
        for info in self.func_infos:
            name = info.func.getName()
            if name:
                all_names.add(name)

        # Visible names (current view)
        row_count = self.table.getRowCount()
        visible_names = set()
        for view_row in range(row_count):
            model_row = self.table.convertRowIndexToModel(view_row)
            if model_row < 0 or model_row >= len(self.func_infos):
                continue
            name = self.func_infos[model_row].func.getName()
            if name:
                visible_names.add(name)

        if not visible_names:
            return

        remaining = all_names.difference(visible_names)

        # If nothing remains, clear filter (show all)
        if not remaining:
            self.filter_field.setText("")
            self.filter_controller.applyFilter()
            return

        parts = [Pattern.quote(n) for n in remaining]
        pattern_body = "|".join(parts)
        regex = "^(?i)(?:%s)$" % pattern_body

        self.column_combo.setSelectedIndex(PyFunctionTableModel.COL_NAME)
        self.mode_combo.setSelectedItem("matches")
        self.filter_field.setText(regex)
        self.filter_controller.applyFilter()
        

class PyFunctionTableMouseListener(object):
    def __init__(self, table, func_infos, goto_service, program, parent,
                 column_combo, mode_combo, filter_field, filter_controller):
        self.table = table
        self.func_infos = func_infos
        self.goto_service = goto_service
        self.program = program
        self.parent = parent
        self.column_combo = column_combo
        self.mode_combo = mode_combo
        self.filter_field = filter_field
        self.filter_controller = filter_controller

    def _showPopup(self, event):
        if not event.isPopupTrigger():
            return
        row = self.table.rowAtPoint(event.getPoint())
        if row < 0:
            return
        if not self.table.isRowSelected(row):
            self.table.setRowSelectionInterval(row, row)
        model_row = self.table.convertRowIndexToModel(row)
        info = self.func_infos[model_row]

        popup = JPopupMenu()

        rename_item = JMenuItem("Rename...")
        py_rename_listener = PyRenameActionListener(info, self.program, self.table, self.parent)
        java_rename_listener = jpype.JProxy(ActionListener, inst=py_rename_listener)
        rename_item.addActionListener(java_rename_listener)
        popup.add(rename_item)

        popup.addSeparator()

        keep_item = JMenuItem("Keep selected in current view")
        py_keep_listener = PyKeepSelectedActionListener(
            self.table, self.func_infos,
            self.column_combo, self.mode_combo, self.filter_field, self.filter_controller
        )
        java_keep_listener = jpype.JProxy(ActionListener, inst=py_keep_listener)
        keep_item.addActionListener(java_keep_listener)
        popup.add(keep_item)

        remove_item = JMenuItem("Remove selected from current view")
        py_remove_listener = PyRemoveSelectedActionListener(
            self.table, self.func_infos,
            self.column_combo, self.mode_combo, self.filter_field, self.filter_controller
        )
        java_remove_listener = jpype.JProxy(ActionListener, inst=py_remove_listener)
        remove_item.addActionListener(java_remove_listener)
        popup.add(remove_item)
        
        remove_view_item = JMenuItem("Remove current view from full table")
        py_remove_view_listener = PyRemoveViewFromFullActionListener(
            self.table, self.func_infos,
            self.column_combo, self.mode_combo, self.filter_field, self.filter_controller
        )
        java_remove_view_listener = jpype.JProxy(ActionListener, inst=py_remove_view_listener)
        remove_view_item.addActionListener(java_remove_view_listener)
        popup.add(remove_view_item)

        popup.show(self.table, event.getX(), event.getY())

    def mouseClicked(self, event):
        if event.getClickCount() == 2 and not event.isPopupTrigger():
            row = self.table.rowAtPoint(event.getPoint())
            if row < 0:
                return
            model_row = self.table.convertRowIndexToModel(row)
            info = self.func_infos[model_row]
            if self.goto_service is None:
                print("GoToService not available; cannot navigate.")
                return
            try:
                self.goto_service.goTo(info.entry)
            except Exception as e:
                print("Failed to navigate to 0x%X: %s" % (info.start, e))
        else:
            self._showPopup(event)

    def mousePressed(self, event):
        self._showPopup(event)

    def mouseReleased(self, event):
        self._showPopup(event)

    def mouseEntered(self, event):  pass
    def mouseExited(self, event):   pass


class PyRefsTableMouseListener(object):
    def __init__(self, table, refs_model, goto_service, mode):
        self.table = table
        self.refs_model = refs_model
        self.goto_service = goto_service
        self.mode = mode

    def mouseClicked(self, event):
        if event.getClickCount() != 2:
            return
        row = self.table.rowAtPoint(event.getPoint())
        if row < 0:
            return
        model_row = self.table.convertRowIndexToModel(row)
        if model_row < 0 or model_row >= self.refs_model.getRowCount():
            return

        if self.mode == "to":
            from_off, to_off = self.refs_model.rows[model_row]
            target_off = from_off
        else:
            from_off, dest_off, dest_name, dest_is_external = self.refs_model.rows[model_row]
            if dest_is_external or dest_off < 0:
                target_off = from_off
            else:
                target_off = dest_off

        addr = toAddr(target_off)
        if addr is None:
            return
        if self.goto_service is None:
            print("GoToService not available; cannot navigate.")
            return
        try:
            self.goto_service.goTo(addr)
        except Exception as e:
            print("Failed to navigate to 0x%X: %s" % (target_off, e))

    def mousePressed(self, event):  pass
    def mouseReleased(self, event): pass
    def mouseEntered(self, event):  pass
    def mouseExited(self, event):   pass


class PyRefsCellRenderer(object):
    """
    Cell renderer for refs tables, with icons in the 'Foreign Val.' column:
      - Is referred by: function icon (caller)
      - Refers to: function icon for internal callee, external icon for external.
    """

    def __init__(self, refs_model, is_refs_to):
        self.refs_model = refs_model
        self.is_refs_to = is_refs_to
        self.base = DefaultTableCellRenderer()
        # Same icons as CallTree:
        self.function_icon = GIcon("icon.plugin.calltree.function")
        self.external_icon = GIcon("icon.plugin.calltree.node.external")

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        comp = self.base.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)

        # Only decorate Foreign Val. column (index 0)
        if column != 0:
            comp.setIcon(None)
            return comp

        comp.setIcon(None)
        model_row = table.convertRowIndexToModel(row)
        if model_row < 0 or model_row >= len(self.refs_model.rows):
            return comp

        ref = self.refs_model.rows[model_row]

        if self.is_refs_to:
            # "Is referred by": foreign value is always a function (caller)
            comp.setIcon(self.function_icon)
        else:
            # "Refers to": foreign value is callee; distinguish external/internal
            if len(ref) >= 4:
                dest_is_external = bool(ref[3])
            else:
                dest_is_external = False
            if dest_is_external:
                comp.setIcon(self.external_icon)
            else:
                comp.setIcon(self.function_icon)

        return comp


class PyFunctionSelectionListener(object):
    def __init__(self, table, func_infos, refs_to_model, refs_from_model, label,
                 refs_to_table, refs_from_table):
        self.table = table
        self.func_infos = func_infos
        self.refs_to_model = refs_to_model
        self.refs_from_model = refs_from_model
        self.label = label
        self.refs_to_table = refs_to_table
        self.refs_from_table = refs_from_table

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        sel_model = self.table.getSelectionModel()
        row = sel_model.getMinSelectionIndex()
        if row < 0:
            cur_info = None
        else:
            row = self.table.convertRowIndexToModel(row)
            if row < 0 or row >= len(self.func_infos):
                cur_info = None
            else:
                cur_info = self.func_infos[row]

        self.refs_to_model.setCurrentFunction(cur_info)
        self.refs_from_model.setCurrentFunction(cur_info)
        self.refs_to_table.revalidate()
        self.refs_to_table.repaint()
        self.refs_from_table.revalidate()
        self.refs_from_table.repaint()

        if cur_info is None:
            self.label.setText("Function")
        else:
            text = "%s %s %s" % (cur_info.type_str, cur_info.name, cur_info.args_str)
            self.label.setText(text)


class PyFilterController(object):
    def __init__(self, table, model, column_combo, mode_combo, text_field):
        self.table = table
        self.model = model
        self.column_combo = column_combo
        self.mode_combo = mode_combo
        self.text_field = text_field

    def applyFilter(self):
        sorter = self.table.getRowSorter()
        if sorter is None or not isinstance(sorter, TableRowSorter):
            return

        text = self.text_field.getText()
        if text is None:
            text = ""
        pattern = text.strip()
        if pattern == "":
            sorter.setRowFilter(None)
            return

        col = self.column_combo.getSelectedIndex()
        mode = self.mode_combo.getSelectedItem()
        if mode is None:
            mode = "contains"

        if mode == "contains":
            escaped = Pattern.quote(pattern)
            regex = "(?i).*" + escaped + ".*"
        else:
            regex = "(?i)" + pattern

        try:
            rf = RowFilter.regexFilter(regex, col)
        except Exception as e:
            print("Invalid regex for filter: %s" % e)
            return
        sorter.setRowFilter(rf)


class PyFilterActionListener(object):
    def __init__(self, controller):
        self.controller = controller

    def actionPerformed(self, event):
        self.controller.applyFilter()

# ----------------------------------------------------------------------
# Color controller
# ----------------------------------------------------------------------

class PyColorController(object):
    def __init__(self, color_config, table, mode_combo, threshold_field):
        self.cfg = color_config
        self.table = table
        self.mode_combo = mode_combo
        self.threshold_field = threshold_field

    def on_mode_changed(self):
        text = self.mode_combo.getSelectedItem()
        if text == "Is referred by":
            self.cfg.mode = ColorConfig.MODE_REFS_TO
        elif text == "Refers to":
            self.cfg.mode = ColorConfig.MODE_REFS_FROM
        else:
            self.cfg.mode = ColorConfig.MODE_TOTAL
        # reset to auto when mode changes
        self.cfg.auto_threshold = True
        self.cfg.manual_threshold = 0
        self.threshold_field.setText("")  # indicate auto
        self.table.repaint()

    def on_threshold_changed(self):
        txt = self.threshold_field.getText()
        if txt is None:
            txt = ""
        txt = txt.strip()
        if txt == "":
            self.cfg.auto_threshold = True
            self.cfg.manual_threshold = 0
        else:
            try:
                val = int(txt, 10)
            except Exception as e:
                print("Invalid threshold value:", e)
                return
            if val <= 0:
                self.cfg.auto_threshold = True
                self.cfg.manual_threshold = 0
            else:
                self.cfg.auto_threshold = False
                self.cfg.manual_threshold = val
        self.table.repaint()


class PyColorModeListener(object):
    def __init__(self, controller):
        self.controller = controller

    def actionPerformed(self, event):
        self.controller.on_mode_changed()


class PyColorThresholdListener(object):
    def __init__(self, controller):
        self.controller = controller

    def actionPerformed(self, event):
        self.controller.on_threshold_changed()


class PyFocusFilterKeyListener(object):
    """
    Implement java.awt.event.KeyListener to catch Ctrl+F and focus the filter field.
    """

    def __init__(self, field):
        self.field = field

    def keyPressed(self, e):
        try:
            if e.getKeyCode() == KeyEvent.VK_F and e.isControlDown():
                print("IFL: Ctrl+F pressed, focusing filter field")
                self.field.requestFocusInWindow()
                self.field.selectAll()
        except Exception as ex:
            print("IFL: FocusFilterKeyListener error:", ex)

    def keyReleased(self, e):
        pass

    def keyTyped(self, e):
        pass

# ----------------------------------------------------------------------
# Column auto-resize helper
# ----------------------------------------------------------------------

def autoResizeColumns(table, maxRows=200):
    """
    Auto-resize columns to fit header + up to maxRows rows.
    Uses table.prepareRenderer(...) so it works with JProxy renderers.
    """
    columnModel = table.getColumnModel()
    rowCount = table.getRowCount()
    rowsToCheck = min(rowCount, maxRows)
    header = table.getTableHeader()

    for col in range(table.getColumnCount()):
        column = columnModel.getColumn(col)
        width = 50  # minimum

        if header is not None:
            renderer = header.getDefaultRenderer()
            comp = renderer.getTableCellRendererComponent(
                table, column.getHeaderValue(), False, False, -1, col
            )
            width = max(width, comp.getPreferredSize().width)

        for row in range(rowsToCheck):
            renderer = table.getCellRenderer(row, col)
            comp = table.prepareRenderer(renderer, row, col)
            width = max(width, comp.getPreferredSize().width)

        column.setPreferredWidth(int(width + 10))

# ----------------------------------------------------------------------
# General helpers: hex parsing, auto-name detection
# ----------------------------------------------------------------------

def parse_hex(s):
    if s is None:
        raise ValueError("None")
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    if not s:
        raise ValueError("empty")
    return int(s, 16)


def is_auto_named_function_name(name):
    return name.startswith("FUN_") or name.startswith("thunk_")

def build_signature_comment(func):
    """
    Build a simple signature comment like "(HKEY, LPCSTR, DWORD)"
    from a function's signature argument types.
    """
    if func is None:
        return ""
    try:
        sig = func.getSignature()
        params = sig.getArguments()
        if not params:
            return ""
        parts = []
        for p in params:
            try:
                dt = p.getDataType()
                type_name = dt.getDisplayName() if dt is not None else "?"
            except Exception:
                type_name = "?"
            parts.append(type_name)
        return "(" + ", ".join(parts) + ")"
    except Exception:
        return ""

# ----------------------------------------------------------------------
# Export helpers: .tag (RVA;name) and .func.csv (RVA,name)
# ----------------------------------------------------------------------

def collect_functions_for_export(dialog_title, program, func_infos, func_table):
    """
    Scope: current view vs all; skip auto-named functions.
    Returns list of FunctionInfo or None if cancelled.
    """
    if program is None or func_infos is None or func_table is None:
        JOptionPane.showMessageDialog(
            None,
            "No program loaded.",
            dialog_title,
            JOptionPane.WARNING_MESSAGE
        )
        return None

    # Scope: current view vs all
    scope_choice = JOptionPane.showConfirmDialog(
        None,
        "Export only functions in current view?\n(Yes = current view, No = all functions)",
        dialog_title,
        JOptionPane.YES_NO_CANCEL_OPTION
    )
    if scope_choice in (JOptionPane.CANCEL_OPTION, JOptionPane.CLOSED_OPTION):
        return None
    only_current_view = (scope_choice == JOptionPane.YES_OPTION)

    # Skip auto-named?
    skip_choice = JOptionPane.showConfirmDialog(
        None,
        "Skip auto-named functions (names starting with \"FUN_\" or \"thunk_\")?",
        dialog_title,
        JOptionPane.YES_NO_CANCEL_OPTION
    )
    if skip_choice in (JOptionPane.CANCEL_OPTION, JOptionPane.CLOSED_OPTION):
        return None
    skip_auto = (skip_choice == JOptionPane.YES_OPTION)

    result = []

    if only_current_view:
        row_count = func_table.getRowCount()
        for view_row in range(row_count):
            model_row = func_table.convertRowIndexToModel(view_row)
            if model_row < 0 or model_row >= len(func_infos):
                continue
            info = func_infos[model_row]
            name = info.func.getName()
            if skip_auto and is_auto_named_function_name(name):
                continue
            result.append(info)
    else:
        for info in func_infos:
            name = info.func.getName()
            if skip_auto and is_auto_named_function_name(name):
                continue
            result.append(info)

    return result


def export_tag(program, func_infos, func_table):
    """
    Export .tag (RVA;name), skipping external functions.
    """
    funcs = collect_functions_for_export("Export .tag", program, func_infos, func_table)
    if funcs is None:
        return

    chooser = JFileChooser()
    chooser.setDialogTitle("Export .tag (RVA;name)")
    chooser.setSelectedFile(File(program.getName() + ".tag"))
    result = chooser.showSaveDialog(None)
    if result != JFileChooser.APPROVE_OPTION:
        return
    out_file = chooser.getSelectedFile()
    if out_file is None:
        return

    image_base = program.getImageBase().getOffset()
    count = 0

    pw = PrintWriter(BufferedWriter(FileWriter(out_file)))
    try:
        for info in funcs:
            func = info.func
            if func.isExternal():
                continue
            entry = func.getEntryPoint()
            if entry is None:
                continue
            va = entry.getOffset()
            rva = va - image_base
            if rva < 0:
                continue
            rva_str = format(rva, "x")
            name = func.getName()
            pw.println("%s;%s" % (rva_str, name))
            count += 1
    finally:
        pw.close()

    JOptionPane.showMessageDialog(
        None,
        "Exported %d functions to %s" % (count, out_file.getAbsolutePath()),
        "Export .tag",
        JOptionPane.INFORMATION_MESSAGE
    )


def export_func_csv(program):
    """
    Export .func.csv (RVA,name) for all internal functions.
    """
    if program is None:
        JOptionPane.showMessageDialog(
            None,
            "No program loaded.",
            "Export .func.csv",
            JOptionPane.WARNING_MESSAGE
        )
        return

    chooser = JFileChooser()
    chooser.setDialogTitle("Export .func.csv (RVA,name)")
    chooser.setSelectedFile(File(program.getName() + ".func.csv"))
    result = chooser.showSaveDialog(None)
    if result != JFileChooser.APPROVE_OPTION:
        return
    out_file = chooser.getSelectedFile()
    if out_file is None:
        return

    image_base = program.getImageBase().getOffset()
    fm = program.getFunctionManager()

    pw = PrintWriter(BufferedWriter(FileWriter(out_file)))
    count = 0
    try:
        funcs_it = fm.getFunctions(True)
        while funcs_it.hasNext():
            func = funcs_it.next()
            if func.isExternal():
                continue
            entry = func.getEntryPoint()
            if entry is None:
                continue
            va = entry.getOffset()
            rva = va - image_base
            if rva < 0:
                continue
            rva_str = format(rva, "x")
            name = func.getName()
            pw.println("%s,%s" % (rva_str, name))
            count += 1
    finally:
        pw.close()

    JOptionPane.showMessageDialog(
        None,
        "Exported %d functions to %s" % (count, out_file.getAbsolutePath()),
        "Export .func.csv",
        JOptionPane.INFORMATION_MESSAGE
    )

# ----------------------------------------------------------------------
# Import helpers: .tag/.csv (RVA;name)
# ----------------------------------------------------------------------

def import_tag_csv(program):
    """
    Import names/comments from .tag or .csv (RVA;name or RVA,name), with:
      - rename if address is a function entry
      - TinyTracer-style section transitions pairing
      - call-match skipping for module.api lines
      - comment stacking at non-function addresses
    """
    if program is None:
        JOptionPane.showMessageDialog(
            None,
            "No program loaded.",
            "Import .tag/.csv",
            JOptionPane.WARNING_MESSAGE
        )
        return

    chooser = JFileChooser()
    chooser.setDialogTitle("Import .tag/.csv (RVA;name or RVA,name)")
    result = chooser.showOpenDialog(None)
    if result != JFileChooser.APPROVE_OPTION:
        return
    in_file = chooser.getSelectedFile()
    if in_file is None:
        return

    image_base = program.getImageBase().getOffset()
    default_base_hex = "0x" + format(image_base, "x")
    base_str = JOptionPane.showInputDialog(
        None,
        "Current module base (hex):",
        default_base_hex
    )
    if base_str is None or base_str.strip() == "":
        base = image_base
    else:
        try:
            base = parse_hex(base_str)
        except Exception:
            JOptionPane.showMessageDialog(
                None,
                "Invalid base; using image base.",
                "Import .tag/.csv",
                JOptionPane.WARNING_MESSAGE
            )
            base = image_base

    fm = program.getFunctionManager()
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    addr_space = program.getAddressFactory().getDefaultAddressSpace()

    renamed = 0
    commented = 0

    # For TinyTracer-style section transitions:
    #   addr1;[sec1] -> [sec2]
    #   addr2;section: [sec2]
    # We pair them so that only addr1 gets the combined from->to comment.
    class Transition(object):
        def __init__(self, from_addr_val, from_section):
            self.from_addr_val = from_addr_val
            self.from_section = from_section

    pending_transitions = {}  # secName -> deque([Transition])

    tx_id = program.startTransaction("Import .tag/.csv names")
    success = False
    try:
        br = open(in_file.getAbsolutePath(), "r")
        try:
            for line in br:
                line = line.strip()
                if not line:
                    continue

                # split by ';' then fallback to ','
                parts = line.split(";", 1)
                if len(parts) < 2:
                    parts = line.split(",", 1)
                    if len(parts) < 2:
                        continue

                addr_chunk = parts[0].strip()
                name = parts[1].strip()
                if not addr_chunk or not name:
                    continue

                try:
                    addr_val = parse_hex(addr_chunk)
                except Exception:
                    continue

                # RVA -> VA if below base
                if addr_val < base:
                    addr_val += base

                addr = addr_space.getAddress(addr_val)
                if addr is None:
                    continue

                # Try to rename function if this is a function entry
                func = fm.getFunctionAt(addr)
                if func is not None:
                    try:
                        func.setName(name, SourceType.USER_DEFINED)
                        renamed += 1
                        continue
                    except Exception as e:
                        print("Rename failed at 0x%X: %s" % (addr_val, e))
                        # fall through to comment logic

                # 1) Section header: "section: [sec]"
                trimmed_name = name.strip()
                lower_name = trimmed_name.lower()

                if lower_name.startswith("section: ["):
                    lb = trimmed_name.find('[')
                    rb = trimmed_name.find(']')
                    if lb >= 0 and rb > lb:
                        sec_name = trimmed_name[lb + 1:rb]  # e.g. ".vmp0"
                        dq = pending_transitions.get(sec_name)
                        if dq:
                            t = dq.pop()  # most recent fromSec->secName
                            from_addr = addr_space.getAddress(t.from_addr_val)
                            if from_addr is not None:
                                msg = "[%s]:%x -> [%s]:%x" % (
                                    t.from_section,
                                    t.from_addr_val,
                                    sec_name,
                                    addr_val
                                )
                                try:
                                    existing = listing.getComment(CommentType.REPEATABLE, from_addr)
                                    if not existing:
                                        listing.setComment(from_addr, CommentType.REPEATABLE, msg)
                                    elif msg not in existing:
                                        listing.setComment(
                                            from_addr,
                                            CommentType.REPEATABLE,
                                            existing + "\n" + msg
                                        )
                                    commented += 1
                                except Exception as e:
                                    print("Failed to set section transition comment:", e)
                    # skip generic comment for section lines
                    continue

                # 2) Section transition line: "[sec1] -> [sec2]"
                if trimmed_name.startswith("[") and "->" in trimmed_name:
                    first_lb = trimmed_name.find('[')
                    first_rb = trimmed_name.find(']')
                    arrow_idx = trimmed_name.find("->")
                    if first_lb >= 0 and first_rb > first_lb and arrow_idx > first_rb:
                        from_sec = trimmed_name[first_lb + 1:first_rb]
                        second_lb = trimmed_name.find('[', arrow_idx)
                        second_rb = trimmed_name.find(']', second_lb)
                        if second_lb >= 0 and second_rb > second_lb:
                            to_sec = trimmed_name[second_lb + 1:second_rb]
                            dq = pending_transitions.get(to_sec)
                            if dq is None:
                                dq = deque()
                                pending_transitions[to_sec] = dq
                            dq.append(Transition(addr_val, from_sec))
                            # don't add this line as generic comment
                            continue

                # 3) Call-match skipping for "module.api"
                skip_comment = False
                full_name = name
                mod_part = ""
                api_part = full_name
                dot_idx = full_name.find('.')
                if dot_idx > 0:
                    mod_part = full_name[:dot_idx].lower()
                    api_part = full_name[dot_idx + 1:]

                if mod_part:
                    instr = listing.getInstructionAt(addr)
                    if instr is not None:
                        for ref in ref_mgr.getReferencesFrom(addr):
                            to = ref.getToAddress()
                            if to is None:
                                continue
                            dest = fm.getFunctionAt(to)
                            if dest is None or not dest.isExternal():
                                continue
                            # module from parent namespace, e.g. "KERNEL32.dll" -> "kernel32"
                            lib_name = dest.getParentNamespace().getName()
                            mod_name = lib_name
                            d = mod_name.find('.')
                            if d > 0:
                                mod_name = mod_name[:d]
                            mod_name = mod_name.lower()
                            dest_name = dest.getName()
                            if mod_name == mod_part and dest_name == api_part:
                                skip_comment = True
                                break
                if skip_comment:
                    continue

                # 4) Generic comment stacking
                try:
                    existing = listing.getComment(CommentType.REPEATABLE, addr)
                    if not existing:
                        listing.setComment(addr, CommentType.REPEATABLE, name)
                    elif name not in existing:
                        listing.setComment(addr, CommentType.REPEATABLE, existing + "\n" + name)
                    commented += 1
                except Exception as e:
                    print("Failed to set comment at 0x%X: %s" % (addr_val, e))
        finally:
            br.close()

        success = True
    except Exception as e:
        print("Error importing .tag/.csv:", e)
    finally:
        program.endTransaction(tx_id, success)

    JOptionPane.showMessageDialog(
        None,
        "Imported %d function names and %d comments from %s" %
        (renamed, commented, in_file.getAbsolutePath()),
        "Import .tag/.csv",
        JOptionPane.INFORMATION_MESSAGE
    )
    
# ----------------------------------------------------------------------
# Import helpers: .imports.txt (PE-sieve)
# ----------------------------------------------------------------------

def strip_import_name(full_name):
    """
    Keep only the API name without module and ordinal:
      "kernel32.CreateFileW#123" -> "CreateFileW"
      "kernel32.CreateFileW" -> "CreateFileW"
    """
    if full_name is None:
        return ""
    s = full_name.strip()
    dot = s.find('.')
    if dot >= 0 and dot + 1 < len(s):
        s = s[dot + 1:]
    hash_idx = s.find('#')
    if hash_idx >= 0:
        s = s[:hash_idx]
    return s.strip()


def import_imports_txt(program):
    """
    Import PE-sieve .imports.txt:
      - Define pointer thunks when memory matches thunkVal
      - Create labels with short import names
      - Add repeatable comments with full import name
      - Add PLATE comments at "IAT at: ..." block headers
    """
    if program is None:
        JOptionPane.showMessageDialog(
            None,
            "No program loaded.",
            "Import .imports.txt",
            JOptionPane.WARNING_MESSAGE
        )
        return

    chooser = JFileChooser()
    chooser.setDialogTitle("Import .imports.txt (PE-sieve)")
    result = chooser.showOpenDialog(None)
    if result != JFileChooser.APPROVE_OPTION:
        return
    in_file = chooser.getSelectedFile()
    if in_file is None:
        return

    image_base = program.getImageBase().getOffset()
    default_base_hex = "0x" + format(image_base, "x")
    base_str = JOptionPane.showInputDialog(
        None,
        "Current module base (hex):",
        default_base_hex
    )
    if base_str is None or base_str.strip() == "":
        base = image_base
    else:
        try:
            base = parse_hex(base_str)
        except Exception:
            JOptionPane.showMessageDialog(
                None,
                "Invalid base; using image base.",
                "Import .imports.txt",
                JOptionPane.WARNING_MESSAGE
            )
            base = image_base

    sym_table = program.getSymbolTable()
    listing = program.getListing()
    mem = program.getMemory()
    ptr_size = program.getDefaultPointerSize()
    addr_space = program.getAddressFactory().getDefaultAddressSpace()

    labels_created = 0
    comments_set = 0
    thunks_defined = 0

    tx_id = program.startTransaction("Import .imports.txt")
    success = False
    try:
        br = open(in_file.getAbsolutePath(), "r")
        try:
            for line in br:
                line = line.strip()
                if not line:
                    continue

                lower = line.lower()
                # IAT header: "IAT at: <hex>"
                if lower.startswith("iat at"):
                    idx = line.find(':')
                    if idx >= 0 and idx + 1 < len(line):
                        addr_str = line[idx + 1:].strip()
                        tokens = addr_str.split()
                        if tokens:
                            addr_token = tokens[0]
                            try:
                                iat_val = parse_hex(addr_token)
                                if iat_val < base:
                                    iat_val += base
                                iat_addr = addr_space.getAddress(iat_val)
                                if iat_addr is not None:
                                    existing_plate = listing.getComment(CommentType.PLATE, iat_addr)
                                    plate_msg = "IAT block (imports.txt) at 0x%s" % format(iat_val, "x")
                                    if not existing_plate:
                                        listing.setComment(iat_addr, CommentType.PLATE, plate_msg)
                                    elif "IAT block" not in existing_plate:
                                        listing.setComment(
                                            iat_addr,
                                            CommentType.PLATE,
                                            existing_plate + "\n" + plate_msg
                                        )
                            except Exception:
                                pass
                    continue

                if line.startswith("---"):
                    continue

                parts = line.split(",", 3)
                if len(parts) < 3:
                    continue
                addr_chunk = parts[0].strip()
                thunk_chunk = parts[1].strip()
                full_name = parts[2].strip()
                if not addr_chunk or not full_name:
                    continue

                try:
                    addr_val = parse_hex(addr_chunk)
                except Exception:
                    continue

                if addr_val < base:
                    addr_val += base

                addr = addr_space.getAddress(addr_val)
                if addr is None:
                    continue

                # Try to define pointer data if stored value matches thunkVal
                try:
                    thunk_val = parse_hex(thunk_chunk)
                    stored = -1
                    if ptr_size == 8:
                        stored = mem.getLong(addr)
                    elif ptr_size == 4:
                        stored = mem.getInt(addr) & 0xffffffff
                    if stored == thunk_val:
                        try:
                            listing.clearCodeUnits(addr, addr, False)
                            listing.createData(addr, PointerDataType.dataType)
                            thunks_defined += 1
                        except Exception:
                            pass
                except Exception:
                    pass

                short_name = strip_import_name(full_name)
                if not short_name:
                    continue

                try:
                    sym_table.createLabel(addr, short_name, SourceType.USER_DEFINED)
                    labels_created += 1
                except Exception:
                    pass

                try:
                    existing = listing.getComment(CommentType.REPEATABLE, addr)
                    if not existing:
                        listing.setComment(addr, CommentType.REPEATABLE, full_name)
                    comments_set += 1
                except Exception:
                    pass

            success = True
        finally:
            br.close()
    except Exception as e:
        print("Error importing .imports.txt:", e)
    finally:
        program.endTransaction(tx_id, success)

    JOptionPane.showMessageDialog(
        None,
        "Imported %d labels, defined %d pointer thunks, and set %d comments from %s" %
        (labels_created, thunks_defined, comments_set, in_file.getAbsolutePath()),
        "Import .imports.txt",
        JOptionPane.INFORMATION_MESSAGE
    )

# ----------------------------------------------------------------------
# Export helpers: params.txt (TinyTracer module;func;argc;signature)
# ----------------------------------------------------------------------

def export_params_txt(program, func_infos, func_table):
    """
    Export TinyTracer-style params.txt with:
      - APIs section: called external APIs grouped by module.
      - Custom Functions section: local/custom functions.

    Format:
      mod;func;argc ; (TYPE, TYPE, ...)
    """
    if program is None or func_infos is None or func_table is None:
        JOptionPane.showMessageDialog(
            None,
            "No program loaded.",
            "Export params.txt",
            JOptionPane.WARNING_MESSAGE
        )
        return

    # Default module name: program name without extension
    prog_name = program.getName()
    default_module = prog_name
    dot = prog_name.rfind('.')
    if dot > 0:
        default_module = prog_name[:dot]

    module_prefix = JOptionPane.showInputDialog(
        None,
        "Module prefix for custom functions (e.g., MyCustomModule):",
        default_module
    )
    if module_prefix is None:
        return  # cancelled
    module_prefix = module_prefix.strip()
    if not module_prefix:
        JOptionPane.showMessageDialog(
            None,
            "Module prefix cannot be empty.",
            "Export params.txt",
            JOptionPane.WARNING_MESSAGE
        )
        return

    # Scope for custom functions: Yes = current view, No = all
    scope_choice = JOptionPane.showConfirmDialog(
        None,
        "Export only custom functions in current view?\n(Yes = current view, No = all functions)",
        "Export params.txt",
        JOptionPane.YES_NO_CANCEL_OPTION
    )
    if scope_choice in (JOptionPane.CANCEL_OPTION, JOptionPane.CLOSED_OPTION):
        return
    only_current_view = (scope_choice == JOptionPane.YES_OPTION)

    # Include APIs section?
    api_choice = JOptionPane.showConfirmDialog(
        None,
        "Include called external APIs section?",
        "Export params.txt",
        JOptionPane.YES_NO_CANCEL_OPTION
    )
    if api_choice in (JOptionPane.CANCEL_OPTION, JOptionPane.CLOSED_OPTION):
        return
    include_apis = (api_choice == JOptionPane.YES_OPTION)

    # Skip auto-named?
    skip_choice = JOptionPane.showConfirmDialog(
        None,
        "Skip auto-named functions (names starting with \"FUN_\" or \"thunk_\")?",
        "Export params.txt",
        JOptionPane.YES_NO_CANCEL_OPTION
    )
    if skip_choice in (JOptionPane.CANCEL_OPTION, JOptionPane.CLOSED_OPTION):
        return
    skip_auto = (skip_choice == JOptionPane.YES_OPTION)

    chooser = JFileChooser()
    chooser.setDialogTitle("Export params.txt (module;func;args)")
    chooser.setSelectedFile(File(default_module + ".params.txt"))
    result = chooser.showSaveDialog(None)
    if result != JFileChooser.APPROVE_OPTION:
        return
    out_file = chooser.getSelectedFile()
    if out_file is None:
        return

    fm = program.getFunctionManager()
    ref_mgr = program.getReferenceManager()

    api_count = 0
    custom_count = 0

    pw = PrintWriter(BufferedWriter(FileWriter(out_file)))
    try:
        # -------------------------------------------------------------
        # APIs section
        # -------------------------------------------------------------
        if include_apis:

            class ApiKey(object):
                def __init__(self, mod, lib_name, name, args, sig_comment):
                    self.mod = mod
                    self.lib_name = lib_name
                    self.name = name
                    self.args = args
                    self.sig_comment = sig_comment
                def __eq__(self, other):
                    if not isinstance(other, ApiKey):
                        return False
                    return (self.mod == other.mod and
                            self.name == other.name and
                            self.args == other.args)
                def __hash__(self):
                    return hash((self.mod, self.name, self.args))

            api_set = set()
            api_list = []

            # Walk all functions (not only current view) to collect external callees
            for info in func_infos:
                for (from_off, dest_off, dest_name, dest_is_external) in info.refs_from:
                    if not dest_is_external:
                        continue
                    from_addr = toAddr(from_off)
                    if from_addr is None:
                        continue
                    # re-resolve external dest function(s) from this call site
                    for ref in ref_mgr.getReferencesFrom(from_addr):
                        to = ref.getToAddress()
                        if to is None:
                            continue
                        dest_func = fm.getFunctionAt(to)
                        if dest_func is None or not dest_func.isExternal():
                            continue

                        lib_name = dest_func.getParentNamespace().getName()
                        mod_name = lib_name
                        d = mod_name.find('.')
                        if d > 0:
                            mod_name = mod_name[:d]
                        mod_name = mod_name.lower()

                        api_name = dest_func.getName()
                        try:
                            args = len(dest_func.getSignature().getArguments())
                        except Exception:
                            args = 0

                        sig_comment = build_signature_comment(dest_func)
                        key = ApiKey(mod_name, lib_name, api_name, args, sig_comment)
                        if key not in api_set:
                            api_set.add(key)
                            api_list.append(key)

            # Sort by module, then name, then args
            api_list.sort(key=lambda k: (k.mod, k.name, k.args))

            # Print header
            header_api = "; --- Called APIs/externals ---"
            frame_api = ";" + "-" * (len(header_api) - 1)
            pw.println(frame_api)
            pw.println(header_api)
            pw.println(frame_api)
            pw.println("")

            current_lib = None
            for k in api_list:
                if k.lib_name != current_lib:
                    current_lib = k.lib_name
                    pw.println("")
                    pw.println("; --- %s ---" % current_lib)

                line = "%s;%s;%d" % (k.mod, k.name, k.args)
                if k.sig_comment:
                    line += " ; " + k.sig_comment
                pw.println(line)
                api_count += 1

            pw.println("")

        # -------------------------------------------------------------
        # Custom Functions section
        # -------------------------------------------------------------
        header_custom = "; --- Custom Functions ---"
        frame = ";" + "-" * (len(header_custom) - 1)
        pw.println(frame)
        pw.println(header_custom)
        pw.println(frame)
        pw.println("")

        if only_current_view:
            row_count = func_table.getRowCount()
            for view_row in range(row_count):
                model_row = func_table.convertRowIndexToModel(view_row)
                if model_row < 0 or model_row >= len(func_infos):
                    continue
                info = func_infos[model_row]
                name = info.func.getName()
                if skip_auto and is_auto_named_function_name(name):
                    continue
                args = info.args_num
                comment = build_signature_comment(info.func)
                line = "%s;%s;%d" % (module_prefix, name, args)
                if comment:
                    line += " ; " + comment
                pw.println(line)
                custom_count += 1
        else:
            for info in func_infos:
                name = info.func.getName()
                if skip_auto and is_auto_named_function_name(name):
                    continue
                args = info.args_num
                comment = build_signature_comment(info.func)
                line = "%s;%s;%d" % (module_prefix, name, args)
                if comment:
                    line += " ; " + comment
                pw.println(line)
                custom_count += 1

    except Exception as e:
        print("Error writing params.txt:", e)
        JOptionPane.showMessageDialog(
            None,
            "Error writing file: %s" % e,
            "Export params.txt",
            JOptionPane.ERROR_MESSAGE
        )
        return
    finally:
        pw.close()

    JOptionPane.showMessageDialog(
        None,
        "Exported %d APIs and %d custom functions to %s" %
        (api_count, custom_count, out_file.getAbsolutePath()),
        "Export params.txt",
        JOptionPane.INFORMATION_MESSAGE
    )

# ----------------------------------------------------------------------
# UI launcher
# ----------------------------------------------------------------------

_ifl_frame = None

def show_ifl_window(program, func_infos):
    tool = state.getTool()
    goto_service = None
    if tool is not None:
        goto_service = tool.getService(GoToService)

    def _create_and_show():
        global _ifl_frame
        try:
            py_func_model = PyFunctionTableModel(func_infos, program)
            java_func_model = jpype.JProxy(TableModel, inst=py_func_model)

            func_table = JTable(java_func_model)
            func_table.setAutoCreateRowSorter(True)
            func_table.setFillsViewportHeight(True)

            sorter = func_table.getRowSorter()
            if sorter is None or not isinstance(sorter, TableRowSorter):
                sorter = TableRowSorter(java_func_model)
                func_table.setRowSorter(sorter)

            # Color config + renderer
            color_cfg = ColorConfig(func_infos)
            py_renderer = PyFunctionCellRenderer(color_cfg)
            java_renderer = jpype.JProxy(TableCellRenderer, inst=py_renderer)
            func_table.setDefaultRenderer(String, java_renderer)
            func_table.setDefaultRenderer(Integer, java_renderer)

            # Filter + color controls panel
            filter_panel = JPanel()
            filter_panel.add(JLabel("Where"))
            column_combo = JComboBox(py_func_model.headers)
            column_combo.setSelectedIndex(PyFunctionTableModel.COL_NAME)
            filter_panel.add(column_combo)

            mode_combo = JComboBox(["contains", "matches"])
            mode_combo.setSelectedIndex(0)
            filter_panel.add(mode_combo)

            filter_field = JTextField(20)
            filter_panel.add(filter_field)

            filter_controller = PyFilterController(func_table, py_func_model, column_combo, mode_combo, filter_field)
            py_filter_listener = PyFilterActionListener(filter_controller)
            java_filter_listener = jpype.JProxy(ActionListener, inst=py_filter_listener)
            filter_field.addActionListener(java_filter_listener)
            column_combo.addActionListener(java_filter_listener)
            mode_combo.addActionListener(java_filter_listener)

            # Color controls
            filter_panel.add(JLabel(" Color by"))
            color_mode_combo = JComboBox(["Total refs", "Is referred by", "Refers to"])
            color_mode_combo.setSelectedIndex(0)
            filter_panel.add(color_mode_combo)

            filter_panel.add(JLabel("Thresh"))
            color_threshold_field = JTextField(4)
            filter_panel.add(color_threshold_field)
            
            # Palette controls
            filter_panel.add(JLabel(" Palette"))
            palette_combo = JComboBox(["Green-Red", "Blue-Orange", "Purple-Cyan"])
            palette_combo.setSelectedIndex(0)
            filter_panel.add(palette_combo)

            color_controller = PyColorController(color_cfg, func_table, color_mode_combo, color_threshold_field)
            py_color_mode_listener = PyColorModeListener(color_controller)
            java_color_mode_listener = jpype.JProxy(ActionListener, inst=py_color_mode_listener)
            color_mode_combo.addActionListener(java_color_mode_listener)

            py_color_thresh_listener = PyColorThresholdListener(color_controller)
            java_color_thresh_listener = jpype.JProxy(ActionListener, inst=py_color_thresh_listener)
            color_threshold_field.addActionListener(java_color_thresh_listener)

            # Palette change → update renderer
            class PyPaletteActionListener(object):
                def __init__(self, renderer):
                    self.renderer = renderer
                def actionPerformed(self, e):
                    sel = palette_combo.getSelectedItem()
                    if sel == "Blue-Orange":
                        self.renderer.set_palette("BLUE_ORANGE")
                    elif sel == "Purple-Cyan":
                        self.renderer.set_palette("PURPLE_CYAN")
                    else:
                        self.renderer.set_palette("GREEN_RED")
                    func_table.repaint()

            py_palette_listener = PyPaletteActionListener(py_renderer)
            java_palette_listener = jpype.JProxy(ActionListener, inst=py_palette_listener)
            palette_combo.addActionListener(java_palette_listener)
            
            top_scroll = JScrollPane(func_table)
            top_panel = JPanel(BorderLayout())
            top_panel.add(filter_panel, BorderLayout.NORTH)
            top_panel.add(top_scroll, BorderLayout.CENTER)

            # Refs models + tables
            py_refs_to_model = PyRefsTableModel(program, "to")
            py_refs_from_model = PyRefsTableModel(program, "from")
            java_refs_to_model = jpype.JProxy(TableModel, inst=py_refs_to_model)
            java_refs_from_model = jpype.JProxy(TableModel, inst=py_refs_from_model)

            refs_to_table = JTable(java_refs_to_model)
            refs_to_table.setAutoCreateRowSorter(True)
            refs_to_table.setFillsViewportHeight(True)

            refs_from_table = JTable(java_refs_from_model)
            refs_from_table.setAutoCreateRowSorter(True)
            refs_from_table.setFillsViewportHeight(True)
            
            # Icons in refs tables (function vs external) on Foreign Val. column
            py_refs_to_renderer = PyRefsCellRenderer(py_refs_to_model, True)
            java_refs_to_renderer = jpype.JProxy(TableCellRenderer, inst=py_refs_to_renderer)
            refs_to_table.setDefaultRenderer(String, java_refs_to_renderer)

            py_refs_from_renderer = PyRefsCellRenderer(py_refs_from_model, False)
            java_refs_from_renderer = jpype.JProxy(TableCellRenderer, inst=py_refs_from_renderer)
            refs_from_table.setDefaultRenderer(String, java_refs_from_renderer)

            frame = JFrame("IFL - Interactive Functions List (Ghidra)")

            # Mouse listeners
            py_func_listener = PyFunctionTableMouseListener(
                func_table, func_infos, goto_service, program, frame,
                column_combo, mode_combo, filter_field, filter_controller
            )
            java_func_listener = jpype.JProxy(MouseListener, inst=py_func_listener)
            func_table.addMouseListener(java_func_listener)

            py_refs_to_listener = PyRefsTableMouseListener(refs_to_table, py_refs_to_model, goto_service, "to")
            java_refs_to_listener = jpype.JProxy(MouseListener, inst=py_refs_to_listener)
            refs_to_table.addMouseListener(java_refs_to_listener)

            py_refs_from_listener = PyRefsTableMouseListener(refs_from_table, py_refs_from_model, goto_service, "from")
            java_refs_from_listener = jpype.JProxy(MouseListener, inst=py_refs_from_listener)
            refs_from_table.addMouseListener(java_refs_from_listener)

            # Selection listener
            label = JLabel("Function")
            py_sel_listener = PyFunctionSelectionListener(
                func_table, func_infos,
                py_refs_to_model, py_refs_from_model, label,
                refs_to_table, refs_from_table
            )
            java_sel_listener = jpype.JProxy(ListSelectionListener, inst=py_sel_listener)
            func_table.getSelectionModel().addListSelectionListener(java_sel_listener)

            tabs = JTabbedPane()
            tabs.addTab("Is referred by", JScrollPane(refs_to_table))
            tabs.addTab("Refers to", JScrollPane(refs_from_table))

            bottom_panel = JPanel(BorderLayout())
            bottom_panel.add(label, BorderLayout.NORTH)
            bottom_panel.add(tabs, BorderLayout.CENTER)
            
            # ------------------------------------------------------------------
            # Button row for import/export
            # ------------------------------------------------------------------
            button_panel = JPanel()
            export_tag_btn = JButton("Export .tag")
            export_csv_btn = JButton("Export .func.csv")
            import_names_btn = JButton("Import .tag/.csv")
            import_imports_btn = JButton("Import .imports.txt")
            export_params_btn = JButton("Export params.txt")

            button_panel.add(export_tag_btn)
            button_panel.add(export_csv_btn)
            button_panel.add(import_names_btn)
            button_panel.add(import_imports_btn)
            button_panel.add(export_params_btn)

            bottom_panel.add(button_panel, BorderLayout.SOUTH)
            
            # Wire export buttons
            class PyExportTagListener(object):
                def __init__(self, program, func_infos, func_table):
                    self.program = program
                    self.func_infos = func_infos
                    self.func_table = func_table
                def actionPerformed(self, e):
                    export_tag(self.program, self.func_infos, self.func_table)

            class PyExportFuncCsvListener(object):
                def __init__(self, program):
                    self.program = program
                def actionPerformed(self, e):
                    export_func_csv(self.program)

            export_tag_listener = PyExportTagListener(program, func_infos, func_table)
            export_tag_btn.addActionListener(
                jpype.JProxy(ActionListener, inst=export_tag_listener)
            )

            export_csv_listener = PyExportFuncCsvListener(program)
            export_csv_btn.addActionListener(
                jpype.JProxy(ActionListener, inst=export_csv_listener)
            )

            # Import .tag/.csv
            class PyImportTagCsvListener(object):
                def __init__(self, program):
                    self.program = program
                def actionPerformed(self, e):
                    import_tag_csv(self.program)

            # Import .imports.txt
            class PyImportImportsTxtListener(object):
                def __init__(self, program):
                    self.program = program
                def actionPerformed(self, e):
                    import_imports_txt(self.program)

            import_tag_listener = PyImportTagCsvListener(program)
            import_names_btn.addActionListener(
                jpype.JProxy(ActionListener, inst=import_tag_listener)
            )

            import_imports_listener = PyImportImportsTxtListener(program)
            import_imports_btn.addActionListener(
                jpype.JProxy(ActionListener, inst=import_imports_listener)
            )

            # Export params.txt
            class PyExportParamsListener(object):
                def __init__(self, program, func_infos, func_table):
                    self.program = program
                    self.func_infos = func_infos
                    self.func_table = func_table
                def actionPerformed(self, e):
                    export_params_txt(self.program, self.func_infos, self.func_table)

            export_params_listener = PyExportParamsListener(program, func_infos, func_table)
            export_params_btn.addActionListener(
                jpype.JProxy(ActionListener, inst=export_params_listener)
            )
            
            # Ctrl+F key listener on main components (function table and refs tables)
            py_focus_listener = PyFocusFilterKeyListener(filter_field)
            java_focus_listener = jpype.JProxy(KeyListener, inst=py_focus_listener)

            func_table.addKeyListener(java_focus_listener)
            refs_to_table.addKeyListener(java_focus_listener)
            refs_from_table.addKeyListener(java_focus_listener)
            filter_field.addKeyListener(java_focus_listener)
            
            split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_panel, bottom_panel)
            split.setResizeWeight(0.5)

            frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            frame.getContentPane().add(split, BorderLayout.CENTER)

            try:
                autoResizeColumns(func_table, maxRows=200)
            except Exception as e:
                print("autoResizeColumns failed:", e)

            frame.setSize(1200, 750)
            frame.setLocationRelativeTo(None)
            frame.setVisible(True)

            global _ifl_frame
            _ifl_frame = frame

        except Exception as e:
            print("Error creating IFL window:", e)

    SwingUtilities.invokeLater(_create_and_show)

# ----------------------------------------------------------------------
# Script entrypoint
# ----------------------------------------------------------------------

def run():
    program = currentProgram
    if program is None:
        print("No active program.")
        return

    func_infos, _ = build_ifl_function_map(program)
    print("IFL function map built: %d functions - launching UI..." % len(func_infos))
    show_ifl_window(program, func_infos)

if __name__ == "__main__":
    run()