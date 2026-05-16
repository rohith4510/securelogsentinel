package com.securelog.analysis;

import com.securelog.Alert;
import com.securelog.LogEvent;
import com.securelog.SecurityReport;

import java.util.ArrayList;
import java.util.List;

public class IocDetector implements SecurityAnalyzer {
    private final IocTrie trie = new IocTrie();

    public IocDetector(List<String> indicators) {
        for (String indicator : indicators) {
            trie.insert(indicator.toLowerCase());
        }
    }

    @Override
    public void process(LogEvent event, SecurityReport report) {
        String searchable = (event.getPath() + " " + event.getMessage()).toLowerCase();
        List<String> matches = trie.findMatches(searchable);

        if (!matches.isEmpty()) {
            report.addAlert(new Alert(
                    event.getTimestamp(),
                    6,
                    "Suspicious indicator match",
                    event.getIp(),
                    "Request contained known suspicious keyword or attack pattern.",
                    "matches=" + matches + ", path=" + event.getPath()
            ));
        }
    }

    private static class IocTrie {
        private final Node root = new Node();

        void insert(String word) {
            Node current = root;
            for (char ch : word.toCharArray()) {
                current = current.children.computeIfAbsent(ch, ignored -> new Node());
            }
            current.word = word;
        }

        List<String> findMatches(String text) {
            List<String> matches = new ArrayList<>();

            for (int start = 0; start < text.length(); start++) {
                Node current = root;
                for (int i = start; i < text.length(); i++) {
                    current = current.children.get(text.charAt(i));
                    if (current == null) {
                        break;
                    }
                    if (current.word != null && !matches.contains(current.word)) {
                        matches.add(current.word);
                    }
                }
            }

            return matches;
        }
    }

    private static class Node {
        private final java.util.Map<Character, Node> children = new java.util.HashMap<>();
        private String word;
    }
}
