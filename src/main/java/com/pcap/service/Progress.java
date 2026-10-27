package com.pcap.service;

/** Where an analysis reports what it is doing: the console's capture queue shows the step and the log lines live. */
public interface Progress {
    /** Steps an analysis walks through, in order; the last one (merging into the site) belongs to the caller. */
    String[] STEPS = {"Starting engines", "Decoding packets", "Zeek + ICSNPP logs", "Other tools", "Merging flows and hosts", "Classifying hosts, extracting images", "Merging into the site"};

    Progress NONE = new Progress() {
        public void step(int n) { }
        public void log(String line) { }
    };

    /** Step {@code n} (1-based, index into {@link #STEPS}) has started. */
    void step(int n);

    void log(String line);

    /** What is going on right now ("Zeek 42% · waiting on tshark"); replaces the previous one, never part of the log. */
    default void status(String text) { }
}
