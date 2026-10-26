// Ghidra headless script: decompile every function into one C file (a reading aid; nothing is compiled from it).
// Function starts from build/analysis/export.json are created first so Ghidra and recomp.py agree.
//   analyzeHeadless <proj_dir> hotd -import THOTD.EXE -scriptPath tools/ghidra
//       -postScript DecompileAll.java build/analysis/export.json build/analysis/decomp.c
// @category Port
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String json = new String(Files.readAllBytes(Paths.get(args[0])));
        // "funcs": [{"start": 4259840, ...}, ...]: pick every "start" value
        Matcher m = Pattern.compile("\"start\": (\\d+)").matcher(json.substring(json.indexOf("\"funcs\""), json.indexOf("\"switches\"")));
        int made = 0;
        while (m.find()) {
            Address a = toAddr(Long.parseLong(m.group(1)));
            if (getFunctionAt(a) == null) {
                disassemble(a);
                if (createFunction(a, null) != null) made++;
            }
        }
        println("created " + made + " functions");
        analyzeChanges(currentProgram);
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(args[1])) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) break;
                DecompileResults r = di.decompileFunction(f, 60, monitor);
                out.println("// ==== " + f.getEntryPoint() + " " + f.getName());
                if (r != null && r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
                else out.println("// decompile failed");
            }
        }
    }
}
