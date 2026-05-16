package com.securelog;

import com.securelog.analysis.BruteForceDetector;
import com.securelog.analysis.IocDetector;
import com.securelog.analysis.PortScanDetector;
import com.securelog.analysis.SecurityAnalyzer;
import com.securelog.analysis.ServiceGraphAnalyzer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        Path inputPath = Path.of(args.length == 0 ? "sample_logs/events.csv" : args[0]);

        try {
            List<LogEvent> events = CsvLogReader.read(inputPath);
            events.sort(Comparator.comparing(LogEvent::getTimestamp));

            SecurityReport report = new SecurityReport(events.size());
            List<SecurityAnalyzer> analyzers = buildAnalyzers();

            for (LogEvent event : events) {
                for (SecurityAnalyzer analyzer : analyzers) {
                    analyzer.process(event, report);
                }
            }

            for (SecurityAnalyzer analyzer : analyzers) {
                analyzer.finish(report);
            }

            report.print();
        } catch (IOException ex) {
            System.err.println("Could not read log file: " + inputPath.toAbsolutePath());
            System.err.println(ex.getMessage());
            System.exit(1);
        } catch (IllegalArgumentException ex) {
            System.err.println("Invalid log data: " + ex.getMessage());
            System.exit(1);
        }
    }

    private static List<SecurityAnalyzer> buildAnalyzers() {
        List<String> indicators = Arrays.asList(
                "../",
                "etc/passwd",
                "wp-login",
                "admin",
                "union",
                "select",
                "<script>",
                "redis",
                "database"
        );

        List<SecurityAnalyzer> analyzers = new ArrayList<>();
        analyzers.add(new BruteForceDetector(5, 10));
        analyzers.add(new PortScanDetector(6, 5));
        analyzers.add(new IocDetector(indicators));
        analyzers.add(new ServiceGraphAnalyzer(5));
        return analyzers;
    }
}
