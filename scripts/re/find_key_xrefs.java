import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class find_key_xrefs extends GhidraScript {

    private void dumpRefs(String label, long va) {
        Address addr = toAddr(va);
        println("== " + label + " @ 0x" + Long.toHexString(va) + " ==");
        var it = currentProgram.getReferenceManager().getReferencesTo(addr);
        int n = 0;
        while (it.hasNext()) {
            var ref = it.next();
            Address from = ref.getFromAddress();
            Function fn = getFunctionContaining(from);
            println("  ref from 0x" + from.toString()
                    + (fn != null ? " in " + fn.getName() + " @ 0x" + fn.getEntryPoint().toString() : ""));
            n++;
        }
        println("  (" + n + " references)");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        dumpRefs("DSA SPKI verify key", Long.parseLong(args[0], 16));
        dumpRefs("server static public", Long.parseLong(args[1], 16));
        dumpRefs("static group P hex-string", Long.parseLong(args[2], 16));
        dumpRefs("ephemeral group P hex-string", Long.parseLong(args[3], 16));
        decompileReferring(Long.parseLong(args[0], 16));
        decompileReferring(Long.parseLong(args[1], 16));
        println("DONE-SCAN");
    }

    /** Decompile every function containing a reference to the given address. */
    private void decompileReferring(long va) {
        var ifc = new ghidra.app.decompiler.DecompInterface();
        ifc.openProgram(currentProgram);
        var addr = toAddr(va);
        var functions = new java.util.TreeMap<Address, Function>();
        var it = currentProgram.getReferenceManager().getReferencesTo(addr);
        while (it.hasNext()) {
            var fn = getFunctionContaining(it.next().getFromAddress());
            if (fn != null) functions.put(fn.getEntryPoint(), fn);
        }
        println("== decompiling " + functions.size() + " function(s) referencing 0x" + Long.toHexString(va) + " ==");
        for (Function fn : functions.values()) {
            var res = ifc.decompileFunction(fn, 120, monitor);
            println("### FUNCTION 0x" + fn.getEntryPoint().toString() + " " + fn.getName());
            println(res.getDecompiledFunction() == null ? "(decompile failed)"
                    : res.getDecompiledFunction().getC());
        }
        ifc.dispose();
        println("DONE-SCAN");
    }
}
