package com.securelog;

import java.time.Instant;

public class LogEvent {
    private final Instant timestamp;
    private final String ip;
    private final String username;
    private final String event;
    private final String service;
    private final int port;
    private final String path;
    private final String status;
    private final String message;

    public LogEvent(
            Instant timestamp,
            String ip,
            String username,
            String event,
            String service,
            int port,
            String path,
            String status,
            String message
    ) {
        this.timestamp = timestamp;
        this.ip = ip;
        this.username = username;
        this.event = event;
        this.service = service;
        this.port = port;
        this.path = path;
        this.status = status;
        this.message = message;
    }

    public static LogEvent fromCsv(String[] row, int lineNumber) {
        if (row.length != 9) {
            throw new IllegalArgumentException("line " + lineNumber + " must contain 9 columns");
        }

        try {
            return new LogEvent(
                    Instant.parse(row[0].trim()),
                    clean(row[1]),
                    clean(row[2]),
                    clean(row[3]).toUpperCase(),
                    clean(row[4]).toLowerCase(),
                    Integer.parseInt(row[5].trim()),
                    clean(row[6]),
                    clean(row[7]).toUpperCase(),
                    clean(row[8])
            );
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("line " + lineNumber + " has invalid values: " + ex.getMessage());
        }
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }

    public boolean isFailedLogin() {
        return "LOGIN".equals(event) && "FAIL".equals(status);
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getIp() {
        return ip;
    }

    public String getUsername() {
        return username;
    }

    public String getEvent() {
        return event;
    }

    public String getService() {
        return service;
    }

    public int getPort() {
        return port;
    }

    public String getPath() {
        return path;
    }

    public String getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }

    public String serviceNode() {
        return service + ":" + port;
    }

    @Override
    public String toString() {
        return timestamp + " " + ip + " " + event + " " + serviceNode() + " " + status + " " + path;
    }
}
