package com.securelog.analysis;

import com.securelog.Alert;
import com.securelog.LogEvent;
import com.securelog.SecurityReport;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

public class PortScanDetector implements SecurityAnalyzer {
    private final int uniquePortThreshold;
    private final Duration window;
    private final Map<String, PortWindow> windowsByIp = new HashMap<>();

    public PortScanDetector(int uniquePortThreshold, int windowMinutes) {
        this.uniquePortThreshold = uniquePortThreshold;
        this.window = Duration.ofMinutes(windowMinutes);
    }

    @Override
    public void process(LogEvent event, SecurityReport report) {
        PortWindow portWindow = windowsByIp.computeIfAbsent(event.getIp(), ignored -> new PortWindow());
        portWindow.add(event);
        portWindow.removeOlderThan(event, window);

        if (portWindow.uniquePortCount() == uniquePortThreshold) {
            report.addAlert(new Alert(
                    event.getTimestamp(),
                    8,
                    "Possible port scan",
                    event.getIp(),
                    "Source touched " + uniquePortThreshold + " unique ports within "
                            + window.toMinutes() + " minutes.",
                    "ports=" + portWindow.describePorts()
            ));
        }
    }

    private static class PortWindow {
        private final Deque<LogEvent> events = new ArrayDeque<>();
        private final Map<Integer, Integer> portCounts = new HashMap<>();

        void add(LogEvent event) {
            events.addLast(event);
            portCounts.merge(event.getPort(), 1, Integer::sum);
        }

        void removeOlderThan(LogEvent current, Duration window) {
            while (!events.isEmpty()
                    && Duration.between(events.peekFirst().getTimestamp(), current.getTimestamp()).compareTo(window) > 0) {
                LogEvent expired = events.removeFirst();
                int newCount = portCounts.get(expired.getPort()) - 1;
                if (newCount == 0) {
                    portCounts.remove(expired.getPort());
                } else {
                    portCounts.put(expired.getPort(), newCount);
                }
            }
        }

        int uniquePortCount() {
            return portCounts.size();
        }

        String describePorts() {
            return portCounts.keySet().toString();
        }
    }
}
