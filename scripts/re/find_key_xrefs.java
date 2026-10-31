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
        println("DONE-SCAN");
    }
}
