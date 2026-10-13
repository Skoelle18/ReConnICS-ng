package com.advisory;

import java.util.Map;

record Asset(String id, String ip, String mac, String vendor, String model, String firmware, Map<String, Object> raw) {

    static Asset from(Object o) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("asset must be an object");
        var m = Json.obj(o);
        String ip = field(m, "ip"), mac = field(m, "mac");
        String id = field(m, "id");
        if (id == null) id = ip != null ? ip : mac;
        if (id == null) throw new IllegalArgumentException("asset needs one of id, ip, mac");
        if (id.length() > 128) throw new IllegalArgumentException("id too long");
        return new Asset(id, ip, mac, field(m, "vendor"), field(m, "model"), field(m, "firmware"), m);
    }

    private static String field(Map<String, Object> m, String k) {
        Object v = m.get(k);
        if (v instanceof Map) v = Json.obj(v).get("value");
        if (v == null) return null;
        if (!(v instanceof String s)) throw new IllegalArgumentException(k + " must be a string");
        s = s.strip();
        if (s.length() > 256) throw new IllegalArgumentException(k + " too long");
        return s.isEmpty() ? null : s;
    }
}
