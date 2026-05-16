package com.securelog;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;

public class SecurityReport {
    private final int totalEvents;
    private final List<Alert> alerts = new ArrayList<>();
    private final Map<String, Integer> riskByIp = new HashMap<>();

    public SecurityReport(int totalEvents) {
        this.totalEvents = totalEvents;
    }

    public void addAlert(Alert alert) {
        alerts.add(alert);
        riskByIp.merge(alert.getSourceIp(), alert.getSeverity(), Integer::sum);
    }

    public void print() {
        alerts.sort(Comparator
                .comparing(Alert::getSeverity).reversed()
                .thenComparing(Alert::getTimestamp));

        System.out.println("=== SecureLog Sentinel Report ===");
        System.out.println("Events analyzed: " + totalEvents);
        System.out.println("Alerts raised: " + alerts.size());
        System.out.println();

        System.out.println("Top risky IPs");
        printTopRiskyIps();
        System.out.println();

        System.out.println("Alerts");
        if (alerts.isEmpty()) {
            System.out.println("- No suspicious activity detected.");
        } else {
            for (Alert alert : alerts) {
                System.out.println("- [" + alert.getSeverity() + "/10] " + alert.getType()
                        + " from " + alert.getSourceIp()
                        + " at " + alert.getTimestamp());
                System.out.println("  " + alert.getDescription());
                System.out.println("  Evidence: " + alert.getEvidence());
            }
        }

        System.out.println();
        System.out.println("DSA used: HashMap, Deque sliding window, HashSet, Trie, Graph adjacency map, PriorityQueue.");
    }

    private void printTopRiskyIps() {
        if (riskByIp.isEmpty()) {
            System.out.println("- None");
            return;
        }

        PriorityQueue<Map.Entry<String, Integer>> maxHeap = new PriorityQueue<>(
                (left, right) -> Integer.compare(right.getValue(), left.getValue())
        );
        maxHeap.addAll(riskByIp.entrySet());

        int printed = 0;
        while (!maxHeap.isEmpty() && printed < 5) {
            Map.Entry<String, Integer> entry = maxHeap.poll();
            System.out.println("- " + entry.getKey() + " risk score " + entry.getValue());
            printed++;
        }
    }
}
