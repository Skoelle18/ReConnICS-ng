package com.reconnics.output;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class IngestSchemaValidatorTest {
    private final IngestSchemaValidator validator = new IngestSchemaValidator(new ObjectMapper());

    @Test
    void acceptsObjectFormWithEvidence() {
        IngestModels.Document doc = new IngestModels.Document();
        doc.source = Map.of("tool", "reconnics-ng");
        IngestModels.Asset a = new IngestModels.Asset();
        a.ip = "10.10.1.31";
        a.protocols = List.of("modbus");
        a.vendor = new IngestModels.FieldObject("Lantronix", "HIGH", "Modbus FC43/14");
        doc.assets = List.of(a);
        assertTrue(validator.validate(doc).isEmpty());
    }

    @Test
    void rejectsMissingIdentifiers() {
        IngestModels.Document doc = new IngestModels.Document();
        IngestModels.Asset a = new IngestModels.Asset();
        a.protocols = List.of("modbus");
        doc.assets = List.of(a);
        assertFalse(validator.validate(doc).isEmpty());
    }

    @Test
    void rejectsBadConfidence() {
        IngestModels.Document doc = new IngestModels.Document();
        IngestModels.Asset a = new IngestModels.Asset();
        a.ip = "1.2.3.4";
        a.vendor = new IngestModels.FieldObject("X", "SUPER", "e");
        doc.assets = List.of(a);
        assertTrue(validator.validate(doc).stream().anyMatch(s -> s.contains("confidence")));
    }
}
