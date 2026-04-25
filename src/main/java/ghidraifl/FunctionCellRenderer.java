package ghidraifl;

import com.formdev.flatlaf.FlatLaf;
import javax.swing.JTable;
import javax.swing.UIManager;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Color;
import java.awt.Component;

public class FunctionCellRenderer extends DefaultTableCellRenderer {

    public enum Palette {
        GREEN_RED,
        BLUE_ORANGE,
        PURPLE_CYAN
    }

    private final ColorConfig cfg;
    private Palette palette = Palette.GREEN_RED;

    private Color importColor;
    private Color lowColor;
    private Color highColor;

    public FunctionCellRenderer(ColorConfig cfg) {
        this.cfg = cfg;
        boolean isDark = detectDarkTheme();
        initColorsForPalette(isDark);
    }

    /**
     * Use FlatLaf if available; fall back to luminance of default table background.
     */
    private boolean detectDarkTheme() {
        try {
            // Ghidra 12.x uses FlatLaf, which has a built-in method to check if the current theme is dark.
            return FlatLaf.isLafDark();
        }
        catch (Throwable t) {
            // Fallback: heuristic using default table background
            Color bg = UIManager.getColor("Table.background");
            if (bg == null) {
                bg = Color.WHITE;
            }
            double lum = 0.2126 * bg.getRed() +
                         0.7152 * bg.getGreen() +
                         0.0722 * bg.getBlue();
            return lum < 128.0;
        }
    }

    private void initColorsForPalette(boolean isDark) {
        switch (palette) {
            case BLUE_ORANGE:
                if (isDark) {
                    importColor = new Color(180, 140, 90);
                    lowColor    = new Color(70, 80, 110);
                    highColor   = new Color(200, 130, 60);
                }
                else {
                    importColor = new Color(255, 220, 180);
                    lowColor    = new Color(210, 220, 240);
                    highColor   = new Color(255, 210, 160);
                }
                break;

            case PURPLE_CYAN:
                if (isDark) {
                    // Dark theme: deeper colors
                    importColor = new Color(180, 120, 180);  // magenta-ish for imports
                    lowColor    = new Color(90,  70,  140);  // dark purple
                    highColor   = new Color(60,  150, 170);  // teal/cyan
                }
                else {
                    // Light theme: lighter versions
                    importColor = new Color(240, 200, 240);
                    lowColor    = new Color(200, 180, 230);
                    highColor   = new Color(180, 230, 240);
                }
                break;

            case GREEN_RED:
            default:
                if (isDark) {
                    importColor = new Color(150, 120, 70);
                    lowColor    = new Color(60,  90,  60);
                    highColor   = new Color(180, 80,  80);
                }
                else {
                    importColor = new Color(255, 230, 180);
                    lowColor    = new Color(220, 240, 220);
                    highColor   = new Color(255, 210, 210);
                }
                break;
        }
    }

    /**
     * Called from the provider when palette dropdown changes.
     */
    public void setPalette(Palette palette) {
        if (palette == null) {
            palette = Palette.GREEN_RED;
        }
        this.palette = palette;
        boolean isDark = detectDarkTheme();
        initColorsForPalette(isDark);
    }

    private Color interp(Color c1, Color c2, float t) {
        t = Math.max(0f, Math.min(1f, t));
        int r = (int) (c1.getRed()   + t * (c2.getRed()   - c1.getRed()));
        int g = (int) (c1.getGreen() + t * (c2.getGreen() - c1.getGreen()));
        int b = (int) (c1.getBlue()  + t * (c2.getBlue()  - c1.getBlue()));
        return new Color(r, g, b);
    }

    @Override
    public Component getTableCellRendererComponent(
        JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {

        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // Do not override selection or if we don't have a config yet
        if (isSelected || cfg == null || cfg.getInfos().isEmpty()) {
            return this;
        }

        int modelRow = table.convertRowIndexToModel(row);
        if (modelRow < 0 || modelRow >= cfg.getInfos().size()) {
            return this;
        }

        FunctionInfo info = cfg.getInfos().get(modelRow);

        Color bg = table.getBackground();

        if (info.isImport()) {
            // Imports always have their own color
            bg = importColor;
        }
        else {
            int metric = cfg.getMetric(info);
            int maxv   = cfg.getMaxForMode();
            int thresh = cfg.getThreshold();

            if (maxv > 0 && metric > 0 && metric >= thresh) {
                int top = Math.max(maxv, thresh + 1);
                float t = (float) (metric - thresh) / (float) (top - thresh);
                bg = interp(lowColor, highColor, t);
            }
        }

        setBackground(bg);
        return this;
    }
}