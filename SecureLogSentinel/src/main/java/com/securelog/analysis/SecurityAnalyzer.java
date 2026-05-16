package com.securelog.analysis;

import com.securelog.LogEvent;
import com.securelog.SecurityReport;

public interface SecurityAnalyzer {
    void process(LogEvent event, SecurityReport report);

    default void finish(SecurityReport report) {
    }
}
