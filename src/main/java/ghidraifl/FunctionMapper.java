package ghidraifl;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.ArrayList;
import java.util.List;

public final class FunctionMapper {

    private FunctionMapper() {
    }

    public static List<FunctionInfo> build(Program program) {
        FunctionManager fm = program.getFunctionManager();
        ReferenceManager refMgr = program.getReferenceManager();
        Listing listing = program.getListing();

        List<FunctionInfo> infos = new ArrayList<>();

        // 1. Build FunctionInfo objects
        for (Function func : fm.getFunctions(true)) {
            FunctionInfo info = new FunctionInfo(program, func);

            classifyImport(info);
            fillTypeAndArgs(info);

            infos.add(info);
        }

        // 2. Build refs_to (callers)
        for (FunctionInfo info : infos) {
            Address entry = info.getEntry();
            if (entry == null) {
                continue;
            }
            for (Reference ref : refMgr.getReferencesTo(entry)) {
                Address from = ref.getFromAddress();
                // Only consider refs from instructions
                if (listing.getInstructionAt(from) == null) {
                    continue;
                }
                info.getRefsTo().add(new RefEntry(from, entry, null, false));
            }
        }

        // 3. Build refs_from (callees)
        for (FunctionInfo info : infos) {
            Function func = info.getFunction();
            if (func.isExternal()) {
                continue;
            }
            AddressSetView body = func.getBody();
            if (body == null || body.isEmpty()) {
                continue;
            }

            InstructionIterator instrIt = listing.getInstructions(body, true);
            while (instrIt.hasNext()) {
                Instruction instr = instrIt.next();
                Address from = instr.getAddress();
                for (Reference ref : refMgr.getReferencesFrom(from)) {
                    Address to = ref.getToAddress();
                    if (to == null) {
                        continue;
                    }
                    // skip internal refs
                    if (info.contains(to)) {
                        continue;
                    }
                    Function dest = fm.getFunctionContaining(to);
                    if (dest == null) {
                        continue;
                    }
                    boolean external = dest.isExternal();
                    Address destEntry = dest.getEntryPoint();  // valid for both internal and external
                    String destName = dest.getName();
                    info.getRefsFrom().add(new RefEntry(from, destEntry, destName, external));
                }
            }
        }

        // 4. Compute total refs
        for (FunctionInfo info : infos) {
            info.setTotalRefs(info.getRefsTo().size() + info.getRefsFrom().size());
        }

        return infos;
    }

    private static void classifyImport(FunctionInfo info) {
        Function func = info.getFunction();
        try {
            if (func.isExternal()) {
                info.setImport(true);
                return;
            }
            if (func.isThunk()) {
                Function thunked = func.getThunkedFunction(true);
                if (thunked != null && thunked.isExternal()) {
                    info.setImport(true);
                    return;
                }
            }
        }
        catch (Exception e) {
            // ignore, leave isImport = false
        }
        info.setImport(false);
    }

    private static void fillTypeAndArgs(FunctionInfo info) {
        Function func = info.getFunction();
        try {
            FunctionSignature sig = func.getSignature();

            // Return type
            DataType retType = sig.getReturnType();
            String retStr = retType != null ? retType.getDisplayName() : "?";

            // Calling convention
            String ccName = sig.getCallingConventionName();
            if (ccName == null) {
                ccName = "";
            }

            String typeStr = ccName.isEmpty() ? retStr : (retStr + " " + ccName);
            info.setTypeString(typeStr);

            // Arguments from signature
            ParameterDefinition[] defs = sig.getArguments();
            info.setArgsNum(defs.length);

            if (defs.length == 0) {
                info.setArgsString("(void)");
            }
            else {
                List<String> parts = new ArrayList<>();
                for (ParameterDefinition def : defs) {
                    DataType pType = def.getDataType();
                    String pTypeStr = pType != null ? pType.getDisplayName() : "?";
                    String pName = def.getName();
                    if (pName == null || pName.isEmpty()) {
                        parts.add(pTypeStr);
                    }
                    else {
                        parts.add(pTypeStr + " " + pName);
                    }
                }
                info.setArgsString("(" + String.join(", ", parts) + ")");
            }
        }
        catch (Exception e) {
            info.setTypeString("?");
            info.setArgsString("()");
            info.setArgsNum(0);
        }
    }
}