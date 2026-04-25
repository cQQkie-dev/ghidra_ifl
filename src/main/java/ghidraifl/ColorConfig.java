package ghidraifl;

import java.util.List;

public class ColorConfig {

    public enum Mode {
        TOTAL,
        REFS_TO,
        REFS_FROM
    }

    private final List<FunctionInfo> infos;

    private Mode mode = Mode.TOTAL;
    private boolean autoThreshold = true;
    private int manualThreshold = 0;

    private final int maxRefsTo;
    private final int maxRefsFrom;
    private final int maxTotal;

    public ColorConfig(List<FunctionInfo> infos) {
        this.infos = infos;

        int maxTo = 0;
        int maxFrom = 0;
        int maxTot = 0;

        for (FunctionInfo info : infos) {
            int to = info.getRefsTo().size();
            int from = info.getRefsFrom().size();
            int tot = info.getTotalRefs();

            if (to > maxTo) {
                maxTo = to;
            }
            if (from > maxFrom) {
                maxFrom = from;
            }
            if (tot > maxTot) {
                maxTot = tot;
            }
        }
        this.maxRefsTo = maxTo;
        this.maxRefsFrom = maxFrom;
        this.maxTotal = maxTot;
    }

    public List<FunctionInfo> getInfos() {
        return infos;
    }

    public Mode getMode() {
        return mode;
    }

    public void setMode(Mode mode) {
        this.mode = mode != null ? mode : Mode.TOTAL;
    }

    public boolean isAutoThreshold() {
        return autoThreshold;
    }

    public void setAutoThreshold(boolean autoThreshold) {
        this.autoThreshold = autoThreshold;
    }

    public int getManualThreshold() {
        return manualThreshold;
    }

    public void setManualThreshold(int manualThreshold) {
        this.manualThreshold = manualThreshold;
    }

    public int getMetric(FunctionInfo info) {
        if (mode == Mode.REFS_TO) {
            return info.getRefsTo().size();
        }
        else if (mode == Mode.REFS_FROM) {
            return info.getRefsFrom().size();
        }
        else {
            return info.getTotalRefs();
        }
    }

    public int getMaxForMode() {
        if (mode == Mode.REFS_TO) {
            return maxRefsTo;
        }
        else if (mode == Mode.REFS_FROM) {
            return maxRefsFrom;
        }
        else {
            return maxTotal;
        }
    }

    /**
     * Returns the threshold above which coloring should start.
     * If autoThreshold is true or manualThreshold <= 0:
     *   threshold = max/5 (tunable).
     */
    public int getThreshold() {
        int max = getMaxForMode();
        if (autoThreshold || manualThreshold <= 0) {
            if (max <= 0) {
                return 0;
            }
            return Math.max(1, max / 5);
        }
        return manualThreshold;
    }
}