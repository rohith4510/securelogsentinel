package com.securelog.analysis;

import com.securelog.Alert;
import com.securelog.LogEvent;
import com.securelog.SecurityReport;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

public class BruteForceDetector implements SecurityAnalyzer {
    private final int failureThreshold;
    private final Duration window;
    private final Map<String, Deque<LogEvent>> failuresByIpAndUser = new HashMap<>();

    public BruteForceDetector(int failureThreshold, int windowMinutes) {
        this.failureThreshold = failureThreshold;
        this.window = Duration.ofMinutes(windowMinutes);
    }

    @Override
    public void process(LogEvent event, SecurityReport report) {
        if (!event.isFailedLogin()) {
            return;
        }

        String key = event.getIp() + "|" + event.getUsername();
        Deque<LogEvent> failures = failuresByIpAndUser.computeIfAbsent(key, ignored -> new ArrayDeque<>());
        failures.addLast(event);

        while (!failures.isEmpty()
                && Duration.between(failures.peekFirst().getTimestamp(), event.getTimestamp()).compareTo(window) > 0) {
            failures.removeFirst();
        }

        if (failures.size() == failureThreshold) {
            LogEvent first = failures.peekFirst();
            report.addAlert(new Alert(
                    event.getTimestamp(),
                    9,
                    "Brute force login pattern",
                    event.getIp(),
                    failureThreshold + " failed login attempts for user '" + event.getUsername()
                            + "' within " + window.toMinutes() + " minutes.",
                    "first=" + first.getTimestamp() + ", last=" + event.getTimestamp()
            ));
        }
    }
}
