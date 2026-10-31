import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;

public class sweep_key_refs extends GhidraScript {

    private void sweep(String label, long lo, long hi) {
        var refMgr = currentProgram.getReferenceManager();
        var byTarget = new java.util.TreeMap<Long, java.util.List<Long>>();
        var functions = new java.util.TreeMap<Address, java.util.List<Long>>();
        for (long a = lo; a <= hi; a++) {
            var addr = toAddr(a);
            var it = refMgr.getReferencesTo(addr);
            while (it.hasNext()) {
                var ref_ = it.next();
                long from = ref_.getFromAddress().getOffset();
                byTarget.computeIfAbsent(a, k -> new java.util.ArrayList<Long>()).add(from);
                Function fn = getFunctionContaining(from);
                if (fn != null) {
                    functions.computeIfAbsent(fn.getEntryPoint(), k -> new java.util.ArrayList<Long>()).add(from);
                }
            }
        }
        println("== " + label + " window 0x" + Long.toHexString(lo) + "..0x" + Long.toHexString(hi) + " ==");
        for (var e : byTarget.entrySet()) {
            var sb = new StringBuilder("  target 0x" + Long.toHexString(e.getKey()) + " from:");
            for (Long f : e.getValue()) sb.append(" 0x").append(Long.toHexString(f));
            println(sb.toString());
        }
        println("== functions in window ==");
        for (var e : functions.entrySet()) {
            Function fn = getFunctionContaining(e.getKey());
            var sb = new StringBuilder("  function 0x" + e.getKey().toString() + " " + (fn != null ? fn.getName() : "?") + " refs:");
            for (Long f : e.getValue()) sb.append(" 0x").append(Long.toHexString(f));
            println(sb.toString());
        }
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        long spki = Long.parseLong(a[0], 16);
        long staticPub = Long.parseLong(a[1], 16);
        long staticPStr = Long.parseLong(a[2], 16);
        sweep("SPKI+staticPub key blobs", spki - 0x400, spki + 0x400);
        sweep("group hex-string literals", staticPStr - 0x400, staticPStr + 0x400);
        println("DONE-SWEEP");
    }
}
