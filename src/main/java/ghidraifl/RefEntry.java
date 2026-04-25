package ghidraifl;

import ghidra.program.model.address.Address;

/**
 * Generic reference entry.
 * For "refsFrom" we use:
 *   from: call site
 *   destEntry: callee entry (null for external)
 *   destName: callee name
 *   destExternal: is external
 *
 * For "refsTo" we can use destName == null, destEntry = function entry.
 */
public class RefEntry {

    private final Address from;
    private final Address destEntry;
    private final String destName;
    private final boolean destExternal;

    public RefEntry(Address from, Address destEntry, String destName, boolean destExternal) {
        this.from = from;
        this.destEntry = destEntry;
        this.destName = destName;
        this.destExternal = destExternal;
    }

    public Address getFrom() {
        return from;
    }

    public Address getDestEntry() {
        return destEntry;
    }

    public String getDestName() {
        return destName;
    }

    public boolean isDestExternal() {
        return destExternal;
    }
}