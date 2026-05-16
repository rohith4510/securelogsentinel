C:\Users\plava\Documents\Codex\2026-05-13\teach-me-cyberserurity-tools\SecureLogSentinel
package com.securelog;

import java.time.Instant;

public class Alert {
    private final Instant timestamp;
    private final int severity;
    private final String type;
    private final String sourceIp;
    private final String description;
    private final String evidence;

    public Alert(Instant timestamp, int severity, String type, String sourceIp, String description, String evidence) {
        this.timestamp = timestamp;
        this.severity = severity;
        this.type = type;
        this.sourceIp = sourceIp;
        this.description = description;
        this.evidence = evidence;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public int getSeverity() {
        return severity;
    }

    public String getType() {
        return type;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getDescription() {
        return description;
    }

    public String getEvidence() {
        return evidence;
    }
}
