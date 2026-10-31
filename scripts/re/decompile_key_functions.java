import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class decompile_key_functions extends GhidraScript {

    private Function functionContaining(long addr) {
        return getFunctionContaining(toAddr(addr));
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        var ifc = new ghidra.app.decompiler.DecompInterface();
        ifc.openProgram(currentProgram);

        // one or more "seed" addresses known to sit inside the login-crypto code
        // (from the capstone rip-relative scan): each is an instruction end whose
        // enclosing function touches the key blobs.
        for (String arg : a) {
            long seed = Long.parseLong(arg, 16);
            Address addr = toAddr(seed);
            Function fn = getFunctionContaining(addr);
            println("=== seed 0x" + Long.toHexString(seed) + " -> function " +
                    (fn != null ? fn.getName() + " @ 0x" + fn.getEntryPoint().toString() : "(none)"));
            if (fn == null) continue;
            var res = ifc.decompileFunction(fn, 240, monitor);
            println("### DECOMPILE " + fn.getName() + " 0x" + fn.getEntryPoint().toString());
            println(res.getDecompiledFunction() == null ? "(failed)" : res.getDecompiledFunction().getC());
        }
        println("DONE-DECOMPILE");
    }
}
