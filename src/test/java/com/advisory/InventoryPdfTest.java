package com.advisory;

import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.parser.PdfTextExtractor;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** report.pdf stays a short brief however many assets there are, and still names the ones with alerts. */
class InventoryPdfTest {
    @Test
    void largeInventoryStaysShort() throws Exception {
        StringBuilder j = new StringBuilder("[");
        for (int i = 0; i < 2000; i++)
            j.append(i == 0 ? "" : ",").append("{\"ip\":\"10.0.").append(i / 250).append('.').append(i % 250 + 1).append("\",\"vendor\":\"V").append(i % 30)
             .append("\",\"role\":\"").append(i % 3 == 0 ? "plc" : "hmi").append('"')
             .append(i < 40 ? ",\"alerts\":{\"value\":[\"TEST rule " + i + "\"],\"confidence\":\"MEDIUM\",\"evidence\":\"suricata eve.json\"}" : "").append('}');
        Inventory inv = Inventory.build(j.append(']').toString(), null);
        byte[] pdf = InventoryPdf.pdf(inv, InventoryReport.rank(inv));

        var r = new PdfReader(pdf);
        assertTrue(r.getNumberOfPages() <= 4, r.getNumberOfPages() + " pages");
        String p1 = new PdfTextExtractor(r).getTextFromPage(1) + new PdfTextExtractor(r).getTextFromPage(2);
        assertTrue(p1.contains("top 20 of 40"), p1);
        assertTrue(p1.contains("TEST rule 0"), p1);
    }
}
