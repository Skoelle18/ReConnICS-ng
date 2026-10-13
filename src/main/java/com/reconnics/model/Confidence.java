package com.reconnics.model;

/**
 * Field-level confidence for ingest API {@code HIGH|MEDIUM|LOW}.
 * <ul>
 *   <li>HIGH — identity attribute decoded from a validated identity response</li>
 *   <li>MEDIUM — structurally validated protocol evidence without a direct identity object</li>
 *   <li>LOW — port heuristic or weak association only</li>
 * </ul>
 */
public enum Confidence {
    HIGH,
    MEDIUM,
    LOW;

    public String wire() {
        return name();
    }
}
