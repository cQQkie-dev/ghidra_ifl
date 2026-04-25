package ghidraifl;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

import docking.ComponentProvider;
import generic.theme.GIcon;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import resources.Icons;
import resources.ResourceManager;

public class IFLProvider extends ComponentProvider {

    private final PluginTool tool;
    private JPanel mainPanel;

    private JTable functionTable;
    private FunctionTableModel functionTableModel;
    private TableRowSorter<FunctionTableModel> functionSorter;

    private JTable refsToTable;
    private JTable refsFromTable;
    private RefsTableModel refsToModel;
    private RefsTableModel refsFromModel;

    private JLabel functionLabel;

    // Filter controls
    private JComboBox<String> filterColumnCombo;
    private JComboBox<String> filterModeCombo;
    private JTextField filterField;

    // Color controls
    private JComboBox<String> colorModeCombo;
    private JTextField thresholdField;
    private ColorConfig colorConfig;
    private JComboBox<String> paletteCombo;

    // Import/export buttons
    private JButton exportTagButton;
    private JButton exportCsvButton;
    private JButton importNamesButton;
    private JButton importImportsButton;
    private JButton exportParamsButton;

    private boolean liveUpdate = true;
    
    private Program currentProgram;
    private boolean listenersInitialized = false;
    private FunctionCellRenderer tableRenderer;
    
    public IFLProvider(PluginTool tool, String owner) {
        super(tool, "Interactive Functions List (IFL)", owner);
        this.tool = tool;
        setIcon(ResourceManager.loadImage("images/ifl.png"));
        buildUI();
        setVisible(true);
    }

    private void buildUI() {
        mainPanel = new JPanel(new BorderLayout());

        // ------------------------------------------------------------------
        // Top filter + color controls
        // ------------------------------------------------------------------
        JPanel filterPanel = new JPanel();
        filterPanel.add(new JLabel("Where"));

        filterColumnCombo = new JComboBox<>();
        filterPanel.add(filterColumnCombo);

        filterModeCombo = new JComboBox<>(new String[] { "contains", "matches" });
        filterPanel.add(filterModeCombo);

        filterField = new JTextField(20);
        filterPanel.add(filterField);

        filterPanel.add(new JLabel(" Color by"));
        colorModeCombo = new JComboBox<>(new String[] { "Total refs", "Is referred by", "Refers to" });
        filterPanel.add(colorModeCombo);

        filterPanel.add(new JLabel("Threshold"));
        thresholdField = new JTextField(4);
        filterPanel.add(thresholdField);

        // Palette controls
        filterPanel.add(new JLabel("Palette"));
        paletteCombo = new JComboBox<>(new String[] { "Green-Red", "Blue-Orange", "Purple-Cyan" });
        filterPanel.add(paletteCombo);

        JCheckBox liveUpdateCheck = new JCheckBox("Live update", true);
        liveUpdateCheck.addActionListener(e -> liveUpdate = liveUpdateCheck.isSelected());
        filterPanel.add(liveUpdateCheck);
        
        functionTable = new JTable();
        JScrollPane topScroll = new JScrollPane(functionTable);

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(filterPanel, BorderLayout.NORTH);
        topPanel.add(topScroll, BorderLayout.CENTER);

        // ------------------------------------------------------------------
        // Bottom refs pane
        // ------------------------------------------------------------------
        refsToModel = new RefsTableModel(RefsTableModel.Mode.REFS_TO);
        refsFromModel = new RefsTableModel(RefsTableModel.Mode.REFS_FROM);

        refsToTable = new JTable(refsToModel);
        refsFromTable = new JTable(refsFromModel);

        refsToTable.setAutoCreateRowSorter(true);
        refsFromTable.setAutoCreateRowSorter(true);
        
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Is referred by", Icons.ARROW_UP_LEFT_ICON, new JScrollPane(refsToTable));
        tabs.addTab("Refers to", Icons.ARROW_DOWN_RIGHT_ICON, new JScrollPane(refsFromTable));

        functionLabel = new JLabel("Function");

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(functionLabel, BorderLayout.NORTH);
        bottomPanel.add(tabs, BorderLayout.CENTER);

        // ------------------------------------------------------------------
        // Button row for import/export
        // ------------------------------------------------------------------
        JPanel buttonPanel = new JPanel();
        exportTagButton = new JButton("Export .tag");
        exportCsvButton = new JButton("Export .func.csv");
        importNamesButton = new JButton("Import .tag/.csv");
        importImportsButton = new JButton("Import .imports.txt");
        exportParamsButton = new JButton("Export params.txt");

        buttonPanel.add(exportTagButton);
        buttonPanel.add(exportCsvButton);
        buttonPanel.add(importNamesButton);
        buttonPanel.add(importImportsButton);
        buttonPanel.add(exportParamsButton);

        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Wire button actions once (they will use currentProgram when clicked)
        exportTagButton.addActionListener(e -> exportTag());
        exportCsvButton.addActionListener(e -> exportFuncCsv());
        importNamesButton.addActionListener(e -> importTagCsv());
        importImportsButton.addActionListener(e -> importImportsTxt());
        exportParamsButton.addActionListener(e -> exportTinyTracerParams());


        // ------------------------------------------------------------------
        // Split pane
        // ------------------------------------------------------------------
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topPanel, bottomPanel);
        split.setResizeWeight(0.5);

        mainPanel.add(split, BorderLayout.CENTER);
    }
    
    public void setProgram(Program program) {
        this.currentProgram = program;
        try {
            if (program == null) {
                functionTable.setModel(new DefaultTableModel());
                refsToModel.setProgram(null);
                refsFromModel.setProgram(null);
                refsToModel.setFunction(null);
                refsFromModel.setFunction(null);
                return;
            }

            List<FunctionInfo> infos = FunctionMapper.build(program);
            System.out.println("IFLProvider.setProgram: built " + infos.size() + " functions");

            functionTableModel = new FunctionTableModel(infos);
            functionSorter = new TableRowSorter<>(functionTableModel);

            functionTable.setModel(functionTableModel);
            functionTable.setRowSorter(functionSorter);

            // ---------------------------------------------------------
            // Color configuration and renderer
            // ---------------------------------------------------------
            colorConfig = new ColorConfig(infos);
            tableRenderer = new FunctionCellRenderer(colorConfig);
            functionTable.setDefaultRenderer(String.class, tableRenderer);
            functionTable.setDefaultRenderer(Integer.class, tableRenderer);
            // ---------------------------------------------------------
            
            // Reapply current color mode & threshold from the UI
            applyColorSettingsFromUI();
            functionTable.repaint();
            
            // Populate filter column combo
            filterColumnCombo.removeAllItems();
            for (int i = 0; i < functionTableModel.getColumnCount(); i++) {
                filterColumnCombo.addItem(functionTableModel.getColumnName(i));
            }
            filterColumnCombo.setSelectedIndex(FunctionTableModel.COL_NAME);

            // refs models get the program
            refsToModel.setProgram(program);
            refsFromModel.setProgram(program);

            // Set icon-rendering for the "Foreign Val." column in both refs tables
            refsToTable.setDefaultRenderer(String.class,
                new RefsCellRenderer(refsToModel, true));
            refsFromTable.setDefaultRenderer(String.class,
                new RefsCellRenderer(refsFromModel, false));

            // ---------------------------------------------------------
            // Attach listeners only once
            // ---------------------------------------------------------
            if (!listenersInitialized) {

                // Palette dropdown -> update renderer palette
                paletteCombo.addActionListener(e -> {
                    String sel = (String) paletteCombo.getSelectedItem();
                    FunctionCellRenderer.Palette p;
                    if ("Blue-Orange".equals(sel)) {
                        p = FunctionCellRenderer.Palette.BLUE_ORANGE;
                    }
                    else if ("Purple-Cyan".equals(sel)) {
                        p = FunctionCellRenderer.Palette.PURPLE_CYAN;
                    }
                    else {
                        p = FunctionCellRenderer.Palette.GREEN_RED;
                    }
                    if (tableRenderer != null) {
                        tableRenderer.setPalette(p);
                        functionTable.repaint();
                    }
                });

                // Filtering: apply on Enter / column / mode changes
                filterField.addActionListener(e -> applyFilter());
                filterColumnCombo.addActionListener(e -> applyFilter());
                filterModeCombo.addActionListener(e -> applyFilter());

                // Color controls: mode + threshold
                colorModeCombo.addActionListener(e -> {
                    String text = (String) colorModeCombo.getSelectedItem();
                    ColorConfig.Mode mode;
                    if ("Is referred by".equals(text)) {
                        mode = ColorConfig.Mode.REFS_TO;
                    }
                    else if ("Refers to".equals(text)) {
                        mode = ColorConfig.Mode.REFS_FROM;
                    }
                    else {
                        mode = ColorConfig.Mode.TOTAL;
                    }
                    colorConfig.setMode(mode);
                    // reset to auto threshold when mode changes
                    colorConfig.setAutoThreshold(true);
                    colorConfig.setManualThreshold(0);
                    thresholdField.setText("");
                    functionTable.repaint();
                });

                thresholdField.addActionListener(e -> {
                    String txt = thresholdField.getText();
                    if (txt == null) {
                        txt = "";
                    }
                    txt = txt.trim();
                    if (txt.isEmpty()) {
                        colorConfig.setAutoThreshold(true);
                        colorConfig.setManualThreshold(0);
                    }
                    else {
                        try {
                            int val = Integer.parseInt(txt);
                            if (val <= 0) {
                                colorConfig.setAutoThreshold(true);
                                colorConfig.setManualThreshold(0);
                            }
                            else {
                                colorConfig.setAutoThreshold(false);
                                colorConfig.setManualThreshold(val);
                            }
                        }
                        catch (NumberFormatException ex) {
                            System.err.println("Invalid threshold value: " + ex);
                        }
                    }
                    functionTable.repaint();
                });

                // Selection listener → update refs + label
                functionTable.getSelectionModel().addListSelectionListener(e -> {
                    if (e.getValueIsAdjusting()) {
                        return;
                    }
                    int viewRow = functionTable.getSelectedRow();
                    FunctionInfo info = null;
                    if (viewRow >= 0) {
                        int modelRow = functionTable.convertRowIndexToModel(viewRow);
                        info = functionTableModel.getRow(modelRow);
                    }
                    refsToModel.setFunction(info);
                    refsFromModel.setFunction(info);

                    if (info == null) {
                        functionLabel.setText("Function");
                    }
                    else {
                        functionLabel.setText(info.getTypeString() + " " +
                            info.getFunction().getName() + " " + info.getArgsString());
                    }
                });

                // Mouse listener for function table: double-click + context menu
                functionTable.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                            int viewRow = functionTable.rowAtPoint(e.getPoint());
                            if (viewRow < 0) {
                                return;
                            }
                            int modelRow = functionTable.convertRowIndexToModel(viewRow);
                            FunctionInfo info = functionTableModel.getRow(modelRow);
                            GoToService gotoService = tool.getService(GoToService.class);
                            if (gotoService != null) {
                                gotoService.goTo(info.getEntry());
                            }
                        }
                        else if (e.isPopupTrigger()) {
                            showFunctionTablePopup(e);
                        }
                    }

                    @Override
                    public void mousePressed(MouseEvent e) {
                        if (e.isPopupTrigger()) {
                            showFunctionTablePopup(e);
                        }
                    }

                    @Override
                    public void mouseReleased(MouseEvent e) {
                        if (e.isPopupTrigger()) {
                            showFunctionTablePopup(e);
                        }
                    }
                });

                // Double-click on "Is referred by" → go to caller
                refsToTable.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                            int viewRow = refsToTable.rowAtPoint(e.getPoint());
                            if (viewRow < 0) {
                                return;
                            }
                            int modelRow = refsToTable.convertRowIndexToModel(viewRow);
                            RefEntry ref = refsToModel.getRow(modelRow);
                            Address target = ref.getFrom();  // caller address
                            GoToService gotoService = tool.getService(GoToService.class);
                            if (gotoService != null && target != null) {
                                gotoService.goTo(target);
                            }
                        }
                    }
                });

                // Double-click on "Refers to" → internal callee → entry; external → call site
                refsFromTable.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                            int viewRow = refsFromTable.rowAtPoint(e.getPoint());
                            if (viewRow < 0) {
                                return;
                            }
                            int modelRow = refsFromTable.convertRowIndexToModel(viewRow);
                            RefEntry ref = refsFromModel.getRow(modelRow);

                            Address target;
                            if (ref.isDestExternal() || ref.getDestEntry() == null) {
                                target = ref.getFrom();
                            }
                            else {
                                target = ref.getDestEntry();
                            }

                            GoToService gotoService = tool.getService(GoToService.class);
                            if (gotoService != null && target != null) {
                                gotoService.goTo(target);
                            }
                        }
                    }
                });

                listenersInitialized = true;
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void applyFilter() {
        if (functionSorter == null) {
            return;
        }

        String text = filterField.getText();
        if (text == null) {
            text = "";
        }
        text = text.trim();
        if (text.isEmpty()) {
            functionSorter.setRowFilter(null);
            return;
        }

        int col = filterColumnCombo.getSelectedIndex();
        if (col < 0) {
            col = FunctionTableModel.COL_NAME;
        }

        String mode = (String) filterModeCombo.getSelectedItem();
        if (mode == null) {
            mode = "contains";
        }

        String regex;
        if ("contains".equals(mode)) {
            String escaped = Pattern.quote(text);
            regex = "(?i).*" + escaped + ".*";
        } else { // "matches"
            regex = "(?i)" + text;
        }

        try {
            RowFilter<FunctionTableModel, Integer> rf = RowFilter.regexFilter(regex, col);
            functionSorter.setRowFilter(rf);
        } catch (Exception e) {
            System.err.println("Invalid regex for filter: " + e);
        }
    }
    
    private void applyColorSettingsFromUI() {
        if (colorConfig == null) {
            return;
        }

        // Mode from combo
        String modeText = (String) colorModeCombo.getSelectedItem();
        ColorConfig.Mode mode;
        if ("Is referred by".equals(modeText)) {
            mode = ColorConfig.Mode.REFS_TO;
        }
        else if ("Refers to".equals(modeText)) {
            mode = ColorConfig.Mode.REFS_FROM;
        }
        else {
            mode = ColorConfig.Mode.TOTAL;
        }
        colorConfig.setMode(mode);

        // Threshold from text field
        String txt = thresholdField.getText();
        if (txt == null) {
            txt = "";
        }
        txt = txt.trim();
        if (txt.isEmpty()) {
            colorConfig.setAutoThreshold(true);
            colorConfig.setManualThreshold(0);
        }
        else {
            try {
                int val = Integer.parseInt(txt);
                if (val <= 0) {
                    colorConfig.setAutoThreshold(true);
                    colorConfig.setManualThreshold(0);
                }
                else {
                    colorConfig.setAutoThreshold(false);
                    colorConfig.setManualThreshold(val);
                }
            }
            catch (NumberFormatException e) {
                // On invalid input, fall back to auto
                colorConfig.setAutoThreshold(true);
                colorConfig.setManualThreshold(0);
            }
        }
    }
    
    public void refresh() {
        // Rebuild the view for the current program
        setProgram(currentProgram);
    }
    
    // focus search field for match/contains query
    public void focusSearchField() {
        if (filterField != null) {
            filterField.requestFocusInWindow();
            filterField.selectAll();  // optional: select existing text
        }
    }
    
    // ----------------------------------------------------------------------
    // Refs pane: Decorate ref functions with default icons
    // ----------------------------------------------------------------------
    private static class RefsCellRenderer extends DefaultTableCellRenderer {

        private final RefsTableModel model;
        private final boolean isRefsTo; // true for "Is referred by", false for "Refers to"
        // Match CallTree's icons:
        private final Icon functionIcon = new GIcon("icon.plugin.calltree.function");
        private final Icon externalIcon = new GIcon("icon.plugin.calltree.node.external");

        RefsCellRenderer(RefsTableModel model, boolean isRefsTo) {
            this.model = model;
            this.isRefsTo = isRefsTo;
            setOpaque(true);
        }

        @Override
        public Component getTableCellRendererComponent(
            JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {

            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            // Only decorate the "Foreign Val." column (column 0)
            if (column != 0) {
                setIcon(null);
                return this;
            }

            setIcon(null); // default

            int modelRow = table.convertRowIndexToModel(row);
            if (modelRow < 0 || modelRow >= model.getRowCount()) {
                return this;
            }

            RefEntry ref = model.getRow(modelRow);

            if (isRefsTo) {
                // "Is referred by": foreign value is always a function (caller)
                setIcon(functionIcon);
            }
            else {
                // "Refers to": foreign value is the callee; distinguish internal vs external
                if (ref.isDestExternal()) {
                    setIcon(externalIcon);
                }
                else {
                    setIcon(functionIcon);
                }
            }

            return this;
        }
    }
    
    // ----------------------------------------------------------------------
    // Context menu actions: Rename / Keep / Remove
    // ----------------------------------------------------------------------

    private void showFunctionTablePopup(MouseEvent e) {
        if (functionTableModel == null) {
            return;
        }
        int viewRow = functionTable.rowAtPoint(e.getPoint());
        if (viewRow < 0) {
            return;
        }
        if (!functionTable.isRowSelected(viewRow)) {
            functionTable.setRowSelectionInterval(viewRow, viewRow);
        }

        JPopupMenu popup = new JPopupMenu();

        JMenuItem renameItem = new JMenuItem("Rename...");
        renameItem.addActionListener(ev -> renameSelectedFunction());
        popup.add(renameItem);

        popup.addSeparator();

        JMenuItem keepItem = new JMenuItem("Keep selected in current view");
        keepItem.addActionListener(ev -> keepSelectedInView());
        popup.add(keepItem);

        JMenuItem removeItem = new JMenuItem("Remove selected from current view");
        removeItem.addActionListener(ev -> removeSelectedFromView());
        popup.add(removeItem);
        
        JMenuItem removeViewItem = new JMenuItem("Remove current view from full table");
        removeViewItem.addActionListener(ev -> removeCurrentViewFromFullTable());
        popup.add(removeViewItem);

        popup.show(functionTable, e.getX(), e.getY());
    }

    private void renameSelectedFunction() {
        if (currentProgram == null || functionTableModel == null) {
            return;
        }
        int viewRow = functionTable.getSelectedRow();
        if (viewRow < 0) {
            return;
        }
        int modelRow = functionTable.convertRowIndexToModel(viewRow);
        FunctionInfo info = functionTableModel.getRow(modelRow);

        String currentName = info.getFunction().getName();
        String newName = JOptionPane.showInputDialog(
            mainPanel,
            "New function name:",
            currentName
        );
        if (newName == null) {
            return;
        }
        newName = newName.trim();
        if (newName.isEmpty() || newName.equals(currentName)) {
            return;
        }

        int tx = currentProgram.startTransaction("Rename function");
        boolean success = false;
        try {
            info.getFunction().setName(newName, SourceType.USER_DEFINED);
            success = true;
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            currentProgram.endTransaction(tx, success);
        }

        if (success) {
            functionTableModel.fireTableRowsUpdated(modelRow, modelRow);
        }
    }

    private void keepSelectedInView() {
        if (functionSorter == null || functionTableModel == null) {
            return;
        }
        int[] viewRows = functionTable.getSelectedRows();
        if (viewRows == null || viewRows.length == 0) {
            return;
        }

        List<String> names = new ArrayList<>();
        for (int viewRow : viewRows) {
            if (viewRow < 0) {
                continue;
            }
            int modelRow = functionTable.convertRowIndexToModel(viewRow);
            FunctionInfo info = functionTableModel.getRow(modelRow);
            String name = info.getFunction().getName();
            if (name != null && !name.isEmpty()) {
                names.add(name);
            }
        }
        if (names.isEmpty()) {
            return;
        }

        List<String> parts = new ArrayList<>();
        for (String n : names) {
            parts.add(Pattern.quote(n));
        }
        String patternBody = String.join("|", parts);
        String regex = "^(?i)(?:" + patternBody + ")$";

        filterColumnCombo.setSelectedIndex(FunctionTableModel.COL_NAME);
        filterModeCombo.setSelectedItem("matches");
        filterField.setText(regex);

        try {
            RowFilter<FunctionTableModel, Integer> rf =
                RowFilter.regexFilter(regex, FunctionTableModel.COL_NAME);
            functionSorter.setRowFilter(rf);
        } catch (Exception e) {
            System.err.println("Invalid regex for keep filter: " + e);
        }
    }

    private void removeSelectedFromView() {
        if (functionSorter == null || functionTableModel == null) {
            return;
        }
        int rowCount = functionTable.getRowCount();
        if (rowCount <= 0) {
            return;
        }

        // Collect visible names
        List<String> visibleNames = new ArrayList<>();
        for (int viewRow = 0; viewRow < rowCount; viewRow++) {
            int modelRow = functionTable.convertRowIndexToModel(viewRow);
            FunctionInfo info = functionTableModel.getRow(modelRow);
            String name = info.getFunction().getName();
            if (name != null && !name.isEmpty()) {
                visibleNames.add(name);
            }
        }
        if (visibleNames.isEmpty()) {
            return;
        }

        // Selected names
        int[] viewRows = functionTable.getSelectedRows();
        List<String> selectedNames = new ArrayList<>();
        if (viewRows != null) {
            for (int viewRow : viewRows) {
                if (viewRow < 0) {
                    continue;
                }
                int modelRow = functionTable.convertRowIndexToModel(viewRow);
                FunctionInfo info = functionTableModel.getRow(modelRow);
                String name = info.getFunction().getName();
                if (name != null && !name.isEmpty()) {
                    selectedNames.add(name);
                }
            }
        }

        // Remaining = visible - selected
        List<String> remaining = new ArrayList<>();
        outer: for (String n : visibleNames) {
            for (String sel : selectedNames) {
                if (n.equals(sel)) {
                    continue outer;
                }
            }
            remaining.add(n);
        }
        if (remaining.isEmpty()) {
            return;
        }

        List<String> parts = new ArrayList<>();
        for (String n : remaining) {
            parts.add(Pattern.quote(n));
        }
        String patternBody = String.join("|", parts);
        String regex = "^(?i)(?:" + patternBody + ")$";

        filterColumnCombo.setSelectedIndex(FunctionTableModel.COL_NAME);
        filterModeCombo.setSelectedItem("matches");
        filterField.setText(regex);

        try {
            RowFilter<FunctionTableModel, Integer> rf =
                RowFilter.regexFilter(regex, FunctionTableModel.COL_NAME);
            functionSorter.setRowFilter(rf);
        } catch (Exception e) {
            System.err.println("Invalid regex for remove filter: " + e);
        }
    }
    
    /**
     * Remove the entire current view from the full table:
     *   new view = all functions - visible functions.
     *
     * If nothing remains, we clear the filter (show all).
     */
    private void removeCurrentViewFromFullTable() {
        if (functionSorter == null || functionTableModel == null) {
            return;
        }

        // Collect all names from the full model
        int modelRowCount = functionTableModel.getRowCount();
        List<String> allNames = new ArrayList<>();
        for (int modelRow = 0; modelRow < modelRowCount; modelRow++) {
            FunctionInfo info = functionTableModel.getRow(modelRow);
            String name = info.getFunction().getName();
            if (name != null && !name.isEmpty()) {
                allNames.add(name);
            }
        }
        if (allNames.isEmpty()) {
            return;
        }

        // Collect visible names from the current view
        int viewRowCount = functionTable.getRowCount();
        List<String> visibleNames = new ArrayList<>();
        for (int viewRow = 0; viewRow < viewRowCount; viewRow++) {
            int modelRow = functionTable.convertRowIndexToModel(viewRow);
            if (modelRow < 0 || modelRow >= functionTableModel.getRowCount()) {
                continue;
            }
            FunctionInfo info = functionTableModel.getRow(modelRow);
            String name = info.getFunction().getName();
            if (name != null && !name.isEmpty()) {
                visibleNames.add(name);
            }
        }
        if (visibleNames.isEmpty()) {
            return;
        }

        // Remaining = allNames - visibleNames
        List<String> remaining = new ArrayList<>();
        outer:
        for (String n : allNames) {
            for (String vis : visibleNames) {
                if (n.equals(vis)) {
                    continue outer;
                }
            }
            remaining.add(n);
        }

        // If removing the current view would remove everything, clear filter (show all)
        if (remaining.isEmpty()) {
            filterField.setText("");
            applyFilter();
            return;
        }

        // Build regex to keep remaining names
        List<String> parts = new ArrayList<>();
        for (String n : remaining) {
            parts.add(Pattern.quote(n));
        }
        String patternBody = String.join("|", parts);
        String regex = "^(?i)(?:" + patternBody + ")$";

        filterColumnCombo.setSelectedIndex(FunctionTableModel.COL_NAME);
        filterModeCombo.setSelectedItem("matches");
        filterField.setText(regex);
        applyFilter();
    }
    
    // ----------------------------------------------------------------------
    // Helpers: hex parsing, signature building, detect auto-name FUN_XXXX,
    // collection of exports
    // ----------------------------------------------------------------------
    
    private long parseHex(String s) throws NumberFormatException {
        if (s == null) {
            throw new NumberFormatException("null");
        }
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            s = s.substring(2);
        }
        if (s.isEmpty()) {
            throw new NumberFormatException("empty");
        }
        return Long.parseLong(s, 16);
    }
    
    public boolean isLiveUpdateEnabled() {
        return liveUpdate;
    }
    
    private String stripImportName(String fullName) {
        if (fullName == null) {
            return "";
        }
        String s = fullName.trim();
        int dot = s.indexOf('.');
        if (dot >= 0 && dot + 1 < s.length()) {
            s = s.substring(dot + 1);
        }
        int hash = s.indexOf('#');
        if (hash >= 0) {
            s = s.substring(0, hash);
        }
        return s.trim();
    }
    
    /**
     * Build a simple signature comment like "(HKEY, LPCSTR, DWORD)"
     * from a function's signature argument types.
     */
    private String buildSignatureComment(Function f) {
        if (f == null) {
            return "";
        }
        try {
            FunctionSignature sig = f.getSignature();
            ParameterDefinition[] defs = sig.getArguments();
            if (defs == null || defs.length == 0) {
                return "";
            }
            List<String> parts = new ArrayList<>();
            for (ParameterDefinition def : defs) {
                DataType dt = def.getDataType();
                String typeName = (dt != null) ? dt.getDisplayName() : "?";
                parts.add(typeName);
            }
            return "(" + String.join(", ", parts) + ")";
        }
        catch (Exception e) {
            return "";
        }
    }
    
    private boolean isAutoNamed(FunctionInfo info) {
        String name = info.getFunction().getName();
        return name != null && (name.startsWith("FUN_") || name.startsWith("thunk_"));
    }
    
    /**
     * Collect functions for export, with:
     *  - optional restriction to current view
     *  - optional skipping of auto-named functions (FUN_*)
     *
     * @param dialogTitle title for Yes/No/Cancel dialogs
     * @return list of FunctionInfo or null if user cancelled
     */
    private List<FunctionInfo> collectFunctionsForExport(String dialogTitle) {
        if (currentProgram == null || functionTableModel == null) {
            JOptionPane.showMessageDialog(mainPanel,
                "No program loaded.", dialogTitle, JOptionPane.WARNING_MESSAGE);
            return null;
        }

        // Scope: current view vs all
        int scopeChoice = JOptionPane.showConfirmDialog(
            mainPanel,
            "Export only functions in current view?\n(Yes = current view, No = all functions)",
            dialogTitle,
            JOptionPane.YES_NO_CANCEL_OPTION);
        if (scopeChoice == JOptionPane.CANCEL_OPTION || scopeChoice == JOptionPane.CLOSED_OPTION) {
            return null;
        }
        boolean onlyCurrentView = (scopeChoice == JOptionPane.YES_OPTION);

        // Skip auto-named?
        int skipChoice = JOptionPane.showConfirmDialog(
            mainPanel,
            "Skip auto-named functions (names starting with \"FUN_\")?",
            dialogTitle,
            JOptionPane.YES_NO_CANCEL_OPTION);
        if (skipChoice == JOptionPane.CANCEL_OPTION || skipChoice == JOptionPane.CLOSED_OPTION) {
            return null;
        }
        boolean skipAuto = (skipChoice == JOptionPane.YES_OPTION);

        List<FunctionInfo> result = new ArrayList<>();

        if (onlyCurrentView) {
            int rowCount = functionTable.getRowCount();
            for (int viewRow = 0; viewRow < rowCount; viewRow++) {
                int modelRow = functionTable.convertRowIndexToModel(viewRow);
                FunctionInfo info = functionTableModel.getRow(modelRow);
                if (skipAuto && isAutoNamed(info)) {
                    continue;
                }
                result.add(info);
            }
        }
        else {
            int rowCount = functionTableModel.getRowCount();
            for (int modelRow = 0; modelRow < rowCount; modelRow++) {
                FunctionInfo info = functionTableModel.getRow(modelRow);
                if (skipAuto && isAutoNamed(info)) {
                    continue;
                }
                result.add(info);
            }
        }

        return result;
    }
    
    // ----------------------------------------------------------------------
    // Import/export buttons
    // ----------------------------------------------------------------------
    private void exportTag() {
        List<FunctionInfo> funcs = collectFunctionsForExport("Export .tag");
        if (funcs == null) {
            return; // user cancelled
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export .tag (RVA;name)");
        // Default file name: <program>.tag
        chooser.setSelectedFile(new File(currentProgram.getName() + ".tag"));

        int result = chooser.showSaveDialog(mainPanel);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File outFile = chooser.getSelectedFile();
        if (outFile == null) {
            return;
        }

        long imageBase = currentProgram.getImageBase().getOffset();

        int count = 0;
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outFile)))) {
            for (FunctionInfo info : funcs) {
                Function f = info.getFunction();
                if (f.isExternal()) {
                    continue; // skip imports for .tag/.func.csv
                }
                Address entry = info.getEntry();
                if (entry == null) {
                    continue;
                }
                long va = entry.getOffset();
                long rva = va - imageBase;
                if (rva < 0) {
                    continue;
                }
                String rvaStr = Long.toHexString(rva);
                String name = f.getName();
                pw.println(rvaStr + ";" + name);
                count++;
            }
        }
        catch (IOException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(mainPanel,
                "Error writing file: " + e.getMessage(), "Export .tag", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JOptionPane.showMessageDialog(mainPanel,
            "Exported " + count + " functions to " + outFile.getAbsolutePath(),
            "Export .tag", JOptionPane.INFORMATION_MESSAGE);
    }

    private void exportFuncCsv() {
        List<FunctionInfo> funcs = collectFunctionsForExport("Export .func.csv");
        if (funcs == null) {
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export .func.csv (RVA,name)");
        chooser.setSelectedFile(new File(currentProgram.getName() + ".func.csv"));

        int result = chooser.showSaveDialog(mainPanel);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File outFile = chooser.getSelectedFile();
        if (outFile == null) {
            return;
        }

        long imageBase = currentProgram.getImageBase().getOffset();
        FunctionManager fm = currentProgram.getFunctionManager();

        int count = 0;
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outFile)))) {
            for (Function func : fm.getFunctions(true)) {
                if (func.isExternal()) {
                    continue;
                }
                Address entry = func.getEntryPoint();
                if (entry == null) {
                    continue;
                }
                long va = entry.getOffset();
                long rva = va - imageBase;
                if (rva < 0) {
                    continue;
                }
                String rvaStr = Long.toHexString(rva);
                String name = func.getName();
                pw.println(rvaStr + "," + name);
                count++;
            }
        }
        catch (IOException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(mainPanel,
                "Error writing file: " + e.getMessage(), "Export .func.csv", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JOptionPane.showMessageDialog(mainPanel,
            "Exported " + count + " functions to " + outFile.getAbsolutePath(),
            "Export .func.csv", JOptionPane.INFORMATION_MESSAGE);
    }

    private void importTagCsv() {
        if (currentProgram == null) {
            JOptionPane.showMessageDialog(mainPanel,
                "No program loaded.", "Import .tag/.csv", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import .tag/.csv (RVA;name or RVA,name)");
        int result = chooser.showOpenDialog(mainPanel);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File inFile = chooser.getSelectedFile();
        if (inFile == null) {
            return;
        }

        long imageBase = currentProgram.getImageBase().getOffset();
        String defaultBaseHex = "0x" + Long.toHexString(imageBase);
        String baseStr = JOptionPane.showInputDialog(
            mainPanel,
            "Current module base (hex):",
            defaultBaseHex
        );
        long base;
        if (baseStr == null || baseStr.trim().isEmpty()) {
            base = imageBase;
        }
        else {
            try {
                base = parseHex(baseStr);
            }
            catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(mainPanel,
                    "Invalid base; using image base.", "Import .tag/.csv", JOptionPane.WARNING_MESSAGE);
                base = imageBase;
            }
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        int renamed = 0;
        int commented = 0;

        int tx = currentProgram.startTransaction("Import .tag/.csv names");
        boolean success = false;

        try (BufferedReader br = new BufferedReader(new FileReader(inFile))) {

            // For TinyTracer-style VM transitions:
            //  addr1;[sec1] -> [sec2]
            //  addr2;section: [sec2]
            // We map sec2 -> deque of pending from-entries
            class Transition {
                final long fromAddr;
                final String fromSection;

                Transition(long fromAddr, String fromSection) {
                    this.fromAddr = fromAddr;
                    this.fromSection = fromSection;
                }
            }
            Map<String, Deque<Transition>> pendingTransitions = new HashMap<>();

            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }

                String[] parts = line.split(";", 2);
                if (parts.length < 2) {
                    parts = line.split(",", 2);
                    if (parts.length < 2) {
                        continue;
                    }
                }

                String addrChunk = parts[0].trim();
                String name = parts[1].trim();
                if (addrChunk.isEmpty() || name.isEmpty()) {
                    continue;
                }

                long addrVal;
                try {
                    addrVal = parseHex(addrChunk);
                }
                catch (NumberFormatException e) {
                    continue;
                }

                // Treat as RVA if below base
                if (addrVal < base) {
                    addrVal += base;
                }

                Address addr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(addrVal);
                if (addr == null) {
                    continue;
                }

                Function f = fm.getFunctionAt(addr);
                if (f != null) {
                    try {
                        f.setName(name, SourceType.USER_DEFINED);
                        renamed++;
                        continue;
                    }
                    catch (Exception ex) {
                        ex.printStackTrace();
                        // fall through to comment logic if rename fails
                    }
                }

                // ------------------------------------------------------------------
                // 1) Handle TinyTracer-style section transitions:
                //    [sec1] -> [sec2]   and   section: [sec2]
                // ------------------------------------------------------------------

                String trimmedName = name.trim();
                String lowerName = trimmedName.toLowerCase();

                // Check for "section: [secName]" line
                if (lowerName.startsWith("section: [")) {
                    int lb = trimmedName.indexOf('[');
                    int rb = trimmedName.indexOf(']');
                    if (lb >= 0 && rb > lb) {
                        String secName = trimmedName.substring(lb + 1, rb); // e.g. ".vmp0"

                        Deque<Transition> deque = pendingTransitions.get(secName);
                        if (deque != null && !deque.isEmpty()) {
                            // Assume most recent "[fromSec] -> [secName]" maps to this section line
                            Transition t = deque.removeLast();

                            Address fromAddr = currentProgram.getAddressFactory()
                                .getDefaultAddressSpace().getAddress(t.fromAddr);
                            if (fromAddr != null) {
                                // build “[fromSec]:from -> [secName]:to”
                                String msg = "[" + t.fromSection + "]:" +
                                    Long.toHexString(t.fromAddr) +
                                    " -> [" + secName + "]:" +
                                    Long.toHexString(addrVal);

                                try {
                                    String existing = listing.getComment(CommentType.REPEATABLE, fromAddr);
                                    if (existing == null || existing.isEmpty()) {
                                        listing.setComment(fromAddr, CommentType.REPEATABLE, msg);
                                    }
                                    else if (!existing.contains(msg)) {
                                        listing.setComment(fromAddr, CommentType.REPEATABLE,
                                            existing + "\n" + msg);
                                    }
                                    commented++;
                                }
                                catch (Exception ex) {
                                    ex.printStackTrace();
                                }
                            }
                        }
                    }

                    // We handled this line as a section header; skip generic comment logic
                    continue;
                }

                // Check for "[sec1] -> [sec2]" transition line
                if (trimmedName.startsWith("[") && trimmedName.contains("->")) {
                    int firstLb = trimmedName.indexOf('[');
                    int firstRb = trimmedName.indexOf(']');
                    int arrowIdx = trimmedName.indexOf("->");
                    if (firstLb >= 0 && firstRb > firstLb && arrowIdx > firstRb) {
                        String fromSec = trimmedName.substring(firstLb + 1, firstRb); // ".text"
                        int secondLb = trimmedName.indexOf('[', arrowIdx);
                        int secondRb = trimmedName.indexOf(']', secondLb);
                        if (secondLb >= 0 && secondRb > secondLb) {
                            String toSec = trimmedName.substring(secondLb + 1, secondRb); // ".vmp0"
                            pendingTransitions
                                .computeIfAbsent(toSec, k -> new ArrayDeque<>())
                                .addLast(new Transition(addrVal, fromSec));
                            // Don't drop the original name as a comment now; use only the from->to form
                            continue;
                        }
                    }
                }

                // ------------------------------------------------------------------
                // 2) Call-match skipping for "module.api" style names
                // ------------------------------------------------------------------
                boolean skipCommentDueToMatchingCall = false;
                String fullName = name;
                String modPart = "";
                String apiPart = fullName;
                int dotIdx = fullName.indexOf('.');
                if (dotIdx > 0) {
                    modPart = fullName.substring(0, dotIdx).toLowerCase();
                    apiPart = fullName.substring(dotIdx + 1);
                }
                if (!modPart.isEmpty()) {
                    Instruction instr = listing.getInstructionAt(addr);
                    if (instr != null) {
                        for (Reference ref : refMgr.getReferencesFrom(addr)) {
                            Address to = ref.getToAddress();
                            if (to == null) {
                                continue;
                            }
                            Function dest = fm.getFunctionAt(to);
                            if (dest == null || !dest.isExternal()) {
                                continue;
                            }

                            // Derive module from parent namespace, e.g. "KERNEL32.dll" -> "kernel32"
                            String libName = dest.getParentNamespace().getName();
                            String modName = libName;
                            int d = modName.indexOf('.');
                            if (d > 0) {
                                modName = modName.substring(0, d);
                            }
                            modName = modName.toLowerCase();

                            String destName = dest.getName(); // e.g. "Process32First"

                            if (modName.equals(modPart) && destName.equals(apiPart)) {
                                skipCommentDueToMatchingCall = true;
                                break;
                            }
                        }
                    }
                }

                if (skipCommentDueToMatchingCall) {
                    continue;
                }

                // ------------------------------------------------------------------
                // 3) Generic comment stacking for everything else
                // ------------------------------------------------------------------
                try {
                    String existing = listing.getComment(CommentType.REPEATABLE, addr);
                    if (existing == null || existing.isEmpty()) {
                        listing.setComment(addr, CommentType.REPEATABLE, name);
                    }
                    else if (!existing.contains(name)) {
                        listing.setComment(addr, CommentType.REPEATABLE, existing + "\n" + name);
                    }
                    commented++;
                }
                catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
            success = true;
        }
        catch (IOException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(mainPanel,
                "Error reading file: " + e.getMessage(), "Import .tag/.csv", JOptionPane.ERROR_MESSAGE);
        }
        finally {
            currentProgram.endTransaction(tx, success);
        }

        JOptionPane.showMessageDialog(mainPanel,
            "Imported " + renamed + " function names and " + commented + " comments from " +
                inFile.getAbsolutePath(),
            "Import .tag/.csv", JOptionPane.INFORMATION_MESSAGE);
    }
    private void importImportsTxt() {
        if (currentProgram == null) {
            JOptionPane.showMessageDialog(mainPanel,
                "No program loaded.", "Import .imports.txt", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import .imports.txt (PE-sieve)");
        int result = chooser.showOpenDialog(mainPanel);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File inFile = chooser.getSelectedFile();
        if (inFile == null) {
            return;
        }

        long imageBase = currentProgram.getImageBase().getOffset();
        String defaultBaseHex = "0x" + Long.toHexString(imageBase);
        String baseStr = JOptionPane.showInputDialog(
            mainPanel,
            "Current module base (hex):",
            defaultBaseHex
        );
        long base;
        if (baseStr == null || baseStr.trim().isEmpty()) {
            base = imageBase;
        }
        else {
            try {
                base = parseHex(baseStr);
            }
            catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(mainPanel,
                    "Invalid base; using image base.", "Import .imports.txt", JOptionPane.WARNING_MESSAGE);
                base = imageBase;
            }
        }

        SymbolTable symTable = currentProgram.getSymbolTable();
        Listing listing = currentProgram.getListing();
        Memory mem = currentProgram.getMemory();
        int ptrSize = currentProgram.getDefaultPointerSize();

        int labelsCreated = 0;
        int commentsSet = 0;
        int thunksDefined = 0;

        int tx = currentProgram.startTransaction("Import .imports.txt");
        boolean success = false;
        try (BufferedReader br = new BufferedReader(new FileReader(inFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                
                String lower = line.toLowerCase();
                
                // Handle IAT block headers: "IAT at: <hex>"
                if (lower.startsWith("iat at")) {
                    int idx = line.indexOf(':');
                    if (idx >= 0 && idx + 1 < line.length()) {
                        String addrStr = line.substring(idx + 1).trim();
                        String[] tokens = addrStr.split("\\s+");
                        if (tokens.length > 0) {
                            String addrToken = tokens[0];
                            try {
                                long iatVal = parseHex(addrToken);
                                // Treat as RVA if below base
                                if (iatVal < base) {
                                    iatVal += base;
                                }

                                Address iatAddr = currentProgram.getAddressFactory()
                                    .getDefaultAddressSpace().getAddress(iatVal);
                                if (iatAddr != null) {
                                    String existingPlate =
                                        listing.getComment(CommentType.PLATE, iatAddr);
                                    String plateMsg = "IAT block (imports.txt) at 0x" +
                                                      Long.toHexString(iatVal);

                                    if (existingPlate == null || existingPlate.isEmpty()) {
                                        listing.setComment(iatAddr, CommentType.PLATE, plateMsg);
                                    }
                                    else if (!existingPlate.contains("IAT block")) {
                                        listing.setComment(
                                            iatAddr,
                                            CommentType.PLATE,
                                            existingPlate + "\n" + plateMsg);
                                    }
                                }
                            }
                            catch (Exception ex) {
                                // Ignore parse/lookup errors for headers
                            }
                        }
                    }
                    continue; // move to next line
                }
                
                // header/separator lines
                if (line.startsWith("---") || line.toLowerCase().startsWith("iat at:")) {
                    continue;
                }

                // Normal entry: RVA, thunkVal, fullName
                String[] parts = line.split(",", 3);
                if (parts.length < 3) {
                    continue;
                }

                String addrChunk = parts[0].trim();
                String thunkChunk = parts[1].trim();
                String fullName = parts[2].trim();

                if (addrChunk.isEmpty() || fullName.isEmpty()) {
                    continue;
                }

                long addrVal;
                try {
                    addrVal = parseHex(addrChunk);
                }
                catch (NumberFormatException e) {
                    continue;
                }

                // Treat as RVA if below base
                if (addrVal < base) {
                    addrVal += base;
                }

                Address addr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(addrVal);
                if (addr == null) {
                    continue;
                }

                // Try to define pointer thunk if memory value matches thunkVal
                try {
                    long thunkVal = parseHex(thunkChunk);    // API pointer from PE-sieve
                    long stored = -1L;
                    if (ptrSize == 8) {
                        stored = mem.getLong(addr);
                    }
                    else if (ptrSize == 4) {
                        stored = mem.getInt(addr) & 0xffffffffL;
                    }
                    if (stored == thunkVal) {
                        try {
                            listing.clearCodeUnits(addr, addr, false);
                            listing.createData(addr, PointerDataType.dataType);
                            thunksDefined++;
                        }
                        catch (Exception ex) {
                            // If createData fails, ignore and continue
                            // ex.printStackTrace();
                        }
                    }
                }
                catch (Exception ex) {
                    // If thunkChunk is not valid hex or memory read fails, just skip pointer creation
                    // ex.printStackTrace();
                }

                String shortName = stripImportName(fullName);
                if (shortName.isEmpty()) {
                    continue;
                }

                try {
                    symTable.createLabel(addr, shortName, SourceType.USER_DEFINED);
                    labelsCreated++;
                }
                catch (Exception ex) {
                    // Label may already exist; ignore errors
                    // ex.printStackTrace();
                }

                try {
                    String existing = listing.getComment(CommentType.REPEATABLE, addr);
                    if (existing == null || existing.isEmpty()) {
                        listing.setComment(addr, CommentType.REPEATABLE, fullName);
                    }
                    commentsSet++;
                }
                catch (Exception ex) {
                    // ignore
                    // ex.printStackTrace();
                }
            }
            success = true;
        }
        catch (IOException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(mainPanel,
                "Error reading file: " + e.getMessage(), "Import .imports.txt", JOptionPane.ERROR_MESSAGE);
        }
        finally {
            currentProgram.endTransaction(tx, success);
        }

        JOptionPane.showMessageDialog(mainPanel,
            "Imported " + labelsCreated + " labels, defined " + thunksDefined +
                " pointer thunks, and set " + commentsSet + " comments from " +
                inFile.getAbsolutePath(),
            "Import .imports.txt", JOptionPane.INFORMATION_MESSAGE);
    }

    private void exportTinyTracerParams() {
        if (currentProgram == null || functionTableModel == null) {
            JOptionPane.showMessageDialog(mainPanel,
                "No program loaded.", "Export params.txt", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        
        
        // Default module name: program name without extension
        String progName = currentProgram.getName();
        String defaultModule = progName;
        int dot = progName.lastIndexOf('.');
        if (dot > 0) {
            defaultModule = progName.substring(0, dot);
        }

        String modulePrefix = JOptionPane.showInputDialog(
            mainPanel,
            "Module prefix for custom functions (e.g., MyCustomModule):",
            defaultModule
        );
        if (modulePrefix == null) {
            return; // cancelled
        }
        modulePrefix = modulePrefix.trim();
        if (modulePrefix.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel,
                "Module prefix cannot be empty.", "Export params.txt", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Scope for custom functions: Yes = current view, No = all custom functions
        int scopeChoice = JOptionPane.showConfirmDialog(
            mainPanel,
            "Export only custom functions in current view?\n(Yes = current view, No = all functions)",
            "Export params.txt",
            JOptionPane.YES_NO_CANCEL_OPTION
        );
        if (scopeChoice == JOptionPane.CANCEL_OPTION || scopeChoice == JOptionPane.CLOSED_OPTION) {
            return;
        }
        boolean onlyCurrentView = (scopeChoice == JOptionPane.YES_OPTION);

        // Include APIs section?
        int apiChoice = JOptionPane.showConfirmDialog(
            mainPanel,
            "Include called external APIs section?",
            "Export params.txt",
            JOptionPane.YES_NO_CANCEL_OPTION
        );
        if (apiChoice == JOptionPane.CANCEL_OPTION || apiChoice == JOptionPane.CLOSED_OPTION) {
            return;
        }
        boolean includeApis = (apiChoice == JOptionPane.YES_OPTION);
        
        int skipChoice = JOptionPane.showConfirmDialog(
                mainPanel,
                "Skip auto-named functions (names starting with \"FUN_\")?",
                "Export params.txt",
                JOptionPane.YES_NO_CANCEL_OPTION);
        if (skipChoice == JOptionPane.CANCEL_OPTION || skipChoice == JOptionPane.CLOSED_OPTION) {
            return;
        }
        boolean skipAuto = (skipChoice == JOptionPane.YES_OPTION);
        
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export params.txt (module;func;args)");
        chooser.setSelectedFile(new File(defaultModule + ".params.txt"));

        int result = chooser.showSaveDialog(mainPanel);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File outFile = chooser.getSelectedFile();
        if (outFile == null) {
            return;
        }

        int customCount = 0;
        int apiCount = 0;
        
        // Collect unique APIs from all functions (not just current view)
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outFile)))) {

            FunctionManager fm = currentProgram.getFunctionManager();

            // -------------------------------------------------------------
            // APIs section
            // -------------------------------------------------------------
            if (includeApis) {
                class ApiKey {
                    final String mod;       // e.g. "advapi32"
                    final String libName;   // e.g. "ADVAPI32.dll"
                    final String name;      // e.g. "RegOpenKeyExA"
                    final int args;
                    final String sigComment; // e.g. "(HKEY, LPCSTR, ...)"

                    ApiKey(String mod, String libName, String name, int args, String sigComment) {
                        this.mod = mod;
                        this.libName = libName;
                        this.name = name;
                        this.args = args;
                        this.sigComment = sigComment;
                    }

                    @Override
                    public boolean equals(Object o) {
                        if (this == o) return true;
                        if (!(o instanceof ApiKey)) return false;
                        ApiKey k = (ApiKey) o;
                        return args == k.args &&
                               mod.equals(k.mod) &&
                               name.equals(k.name);
                    }

                    @Override
                    public int hashCode() {
                        return (mod.hashCode() * 31 + name.hashCode()) * 31 + args;
                    }
                }

                List<ApiKey> apiList = new ArrayList<>();
                java.util.Set<ApiKey> apiSet = new java.util.HashSet<>();

                int modelRowCount = functionTableModel.getRowCount();
                for (int modelRow = 0; modelRow < modelRowCount; modelRow++) {
                    FunctionInfo info = functionTableModel.getRow(modelRow);
                    for (RefEntry ref : info.getRefsFrom()) {
                        if (!ref.isDestExternal()) {
                            continue;
                        }
                        Address destEntry = ref.getDestEntry();
                        if (destEntry == null) {
                            continue;
                        }
                        Function destFunc = fm.getFunctionAt(destEntry);
                        if (destFunc == null) {
                            continue;
                        }

                        // Module name from parent namespace (e.g., "KERNEL32.dll" -> "kernel32")
                        String libName = destFunc.getParentNamespace().getName();
                        String modName = libName;
                        int d = modName.indexOf('.');
                        if (d > 0) {
                            modName = modName.substring(0, d);
                        }
                        modName = modName.toLowerCase();

                        String apiName = destFunc.getName();
                        int args = 0;
                        try {
                            args = destFunc.getSignature().getArguments().length;
                        }
                        catch (Exception ex) {
                            // leave args = 0
                        }

                        String sigComment = buildSignatureComment(destFunc);
                        ApiKey key = new ApiKey(modName, libName, apiName, args, sigComment);
                        if (apiSet.add(key)) {
                            apiList.add(key);
                        }
                    }
                }

                // Sort APIs by module, then name
                apiList.sort((a, b) -> {
                    int c = a.mod.compareTo(b.mod);
                    if (c != 0) return c;
                    c = a.name.compareTo(b.name);
                    if (c != 0) return c;
                    return Integer.compare(a.args, b.args);
                });
                
                String headerApi = "; --- Called APIs/externals ---";
                String frameApi = ";" + "-".repeat(headerApi.length() - 1);
                
                pw.println(frameApi);
                pw.println(headerApi);
                pw.println(frameApi);
                
                String currentLib = null;
                for (ApiKey k : apiList) {
                    if (!k.libName.equals(currentLib)) {
                        currentLib = k.libName;
                        pw.println();
                        pw.println("; --- " + currentLib + " ---");
                    }

                    String line = k.mod + ";" + k.name + ";" + k.args;
                    if (k.sigComment != null && !k.sigComment.isEmpty()) {
                        line += " ; " + k.sigComment;
                    }
                    pw.println(line);
                    apiCount++;
                }
                pw.println();
            }

            // -------------------------------------------------------------
            // Custom Functions section
            // -------------------------------------------------------------
            String headerCustom = "; --- Custom Functions ---";
            String frame = ";" + "-".repeat(headerCustom.length() - 1);
            
            pw.println(frame);
            pw.println(headerCustom);
            pw.println(frame);
            pw.println();

            if (onlyCurrentView) {
                int rowCount = functionTable.getRowCount();
                for (int viewRow = 0; viewRow < rowCount; viewRow++) {
                    int modelRow = functionTable.convertRowIndexToModel(viewRow);
                    FunctionInfo info = functionTableModel.getRow(modelRow);
                    if (skipAuto && isAutoNamed(info)) {
                        continue;
                    }
                    String funcName = info.getFunction().getName();
                    int args = info.getArgsNum();

                    String comment = buildSignatureComment(info.getFunction());
                    String line = modulePrefix + ";" + funcName + ";" + args;
                    if (comment != null && !comment.isEmpty()) {
                        line += " ; " + comment;
                    }
                    pw.println(line);
                    customCount++;
                }
            }
            else {
                int rowCount = functionTableModel.getRowCount();
                for (int modelRow = 0; modelRow < rowCount; modelRow++) {
                    FunctionInfo info = functionTableModel.getRow(modelRow);
                    if (skipAuto && isAutoNamed(info)) {
                        continue;
                    }
                    String funcName = info.getFunction().getName();
                    int args = info.getArgsNum();

                    String comment = buildSignatureComment(info.getFunction());
                    String line = modulePrefix + ";" + funcName + ";" + args;
                    if (comment != null && !comment.isEmpty()) {
                        line += " ; " + comment;
                    }
                    pw.println(line);
                    customCount++;
                }
            }
        }
        catch (IOException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(mainPanel,
                "Error writing file: " + e.getMessage(), "Export params.txt", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JOptionPane.showMessageDialog(mainPanel,
            "Exported " + apiCount + " APIs and " + customCount +
                " custom functions to " + outFile.getAbsolutePath(),
            "Export params.txt", JOptionPane.INFORMATION_MESSAGE);
    }
    
    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
}