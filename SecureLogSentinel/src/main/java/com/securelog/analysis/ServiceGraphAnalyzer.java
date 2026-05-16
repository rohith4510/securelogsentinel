package com.securelog.analysis;

import com.securelog.Alert;
import com.securelog.LogEvent;
import com.securelog.SecurityReport;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ServiceGraphAnalyzer implements SecurityAnalyzer {
    private final int serviceThreshold;
    private final Map<String, Set<String>> servicesByIp = new HashMap<>();
    private final Map<String, Instant> lastSeenByIp = new HashMap<>();

    public ServiceGraphAnalyzer(int serviceThreshold) {
        this.serviceThreshold = serviceThreshold;
    }

    @Override
    public void process(LogEvent event, SecurityReport report) {
        servicesByIp
                .computeIfAbsent(event.getIp(), ignored -> new HashSet<>())
                .add(event.serviceNode());
        lastSeenByIp.merge(event.getIp(), event.getTimestamp(), (left, right) -> right.isAfter(left) ? right : left);
    }

    @Override
    public void finish(SecurityReport report) {
        for (Map.Entry<String, Set<String>> entry : servicesByIp.entrySet()) {
            if (entry.getValue().size() >= serviceThreshold) {
                report.addAlert(new Alert(
                        lastSeenByIp.getOrDefault(entry.getKey(), Instant.EPOCH),
                        5,
                        "Broad service access",
                        entry.getKey(),
                        "Source IP interacted with many distinct services, which may indicate reconnaissance.",
                        "services=" + entry.getValue()
                ));
            }
        }
    }
}
