import com.antirat.scanner.JarScanner;
import com.antirat.scanner.ScanReport;
import java.nio.file.Path;
import java.util.List;

public class BenchmarkScanner {
    public static void main(String[] args) {
        Path p = Path.of("C:/Users/Aneesh/Downloads");
        long start = System.currentTimeMillis();
        List<ScanReport> reports = JarScanner.scanModsDirectory(p);
        long duration = System.currentTimeMillis() - start;
        System.out.println("Scan took: " + duration + " ms");
        System.out.println("Reports found: " + reports.size());
        for (ScanReport r : reports) {
            System.out.println(" - " + r.fileName() + ": " + r.findings().size() + " findings");
        }
    }
}
