import soot.*;
import soot.options.Options;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public class Main {

    public static void main(String[] args) throws IOException {

        //Defining Input and Output Paths
        String apkPath      = "A:\\Software security\\lab 1\\demo.apk";
        String androidJars  = "C:\\Users\\aparn\\AppData\\Local\\Android\\Sdk\\platforms";
        String csvPath      = "A:\\Software security\\lab 1\\sensitive_apis.csv";
        String outputDir    = "A:\\Software security\\lab 1\\output";

        // Creating output folder
        new File(outputDir).mkdirs();

        // Loading sensitive APIs from CSV
        Set<String> sensitiveAPIs = loadSensitiveAPIs(csvPath);

        // Configuring Soot
        configureSoot(apkPath, androidJars);

        // Analyzing each class and method
        Map<String, int[]> apiCount = new HashMap<>();
        Map<String, Set<String>> apiFunctions = new HashMap<>();

        for (SootClass sc : Scene.v().getApplicationClasses()) {
            for (SootMethod sm : sc.getMethods()) {

                if (!sm.isConcrete()) continue;

                Body body = sm.retrieveActiveBody();
                String methodName = sm.getName() + "()";

                // Generating and saving CFG as .dot file
                saveCFG(body, sm, outputDir);

                // Checking each statement for sensitive API calls
                for (Unit unit : body.getUnits()) {
                    if (((soot.jimple.Stmt) unit).containsInvokeExpr()) {
                        String apiName = ((soot.jimple.Stmt) unit).getInvokeExpr().getMethod().getName();
                        if (sensitiveAPIs.contains(apiName)) {
                            apiCount.computeIfAbsent(apiName, k -> new int[]{0})[0]++;
                            apiFunctions.computeIfAbsent(apiName, k -> new HashSet<>()).add(methodName);
                        }
                    }
                }
            }
        }

        // Writing sensitive API results to output file
        String resultFile = outputDir + "\\sensitive_api_usage.txt";
        try (PrintWriter pw = new PrintWriter(resultFile)) {
            for (String api : apiCount.keySet()) {
                int count = apiCount.get(api)[0];
                String functions = String.join(",", apiFunctions.get(api));
                pw.println(api + ":" + count + ":" + functions);
            }
        }

        System.out.println("[*] Done! Results saved to: " + resultFile);
        System.out.println("[*] CFG dot files saved to: " + outputDir);
    }

    // Loading sensitive API names from CSV
    static Set<String> loadSensitiveAPIs(String csvPath) throws IOException {
        Set<String> apis = new HashSet<>();
        List<String> lines = Files.readAllLines(Paths.get(csvPath));
        for (String line : lines) {
            String[] parts = line.split(",");
            if (parts.length > 1) {
                String name = parts[1].trim();
                if (!name.isEmpty() && !name.equalsIgnoreCase("CallerMethod")) {
                    apis.add(name);
                }
            }
        }
        System.out.println("[*] Loaded " + apis.size() + " sensitive APIs.");
        return apis;
    }

    // Configuring Soot to analyze the APK
    static void configureSoot(String apkPath, String androidJars) {
        G.reset();
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_android_jars("C:\\Users\\aparn\\AppData\\Local\\Android\\Sdk\\platforms");
        Options.v().set_force_android_jar("C:\\Users\\aparn\\AppData\\Local\\Android\\Sdk\\platforms\\android-36.1\\android.jar");
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_force_overwrite(true);
        Scene.v().loadNecessaryClasses();
        System.out.println("[*] Soot loaded " + Scene.v().getClasses().size() + " classes.");
    }

    // Generating CFG and save as .dot file
    static void saveCFG(Body body, SootMethod sm, String outputDir) throws IOException {
        UnitGraph cfg = new ExceptionalUnitGraph(body);

        //replacing special characters
        String fileName = (sm.getDeclaringClass().getName() + "_" + sm.getName()).replaceAll("[^a-zA-Z0-9_]", "_") + ".dot";

        String filePath = outputDir + "\\" + fileName;

        try (PrintWriter pw = new PrintWriter(filePath)) {
            pw.println("digraph \"" + sm.getName() + "\" {");
            for (Unit unit : body.getUnits()) {
                String from = unit.toString().replace("\"", "'");
                for (Unit succ : cfg.getSuccsOf(unit)) {
                    String to = succ.toString().replace("\"", "'");
                    pw.println("  \"" + from + "\" -> \"" + to + "\";");
                }
            }
            pw.println("}");
        }
    }
}