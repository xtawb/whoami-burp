package whoami.burp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * One saved account: a name, a colour, and the session headers that make a
 * request be that account's. The headers are kept as they will be replayed —
 * the whole Cookie header, the Authorization header, any CSRF or API-key
 * header — and the values that identify the account are derived from them.
 *
 * It is a plain record of what passed through the proxy. Nothing here decides
 * when to use it; the extension does that, on an explicit action.
 */
final class Identity {

    private final String id;
    private String name;
    private String colour;                      // a HighlightColor name, or "NONE"
    private String note;
    private String host;                        // where it was first seen, for display
    private final long createdAt;
    private long updatedAt;
    private final LinkedHashMap<String, String> headers;
    private final java.util.concurrent.atomic.AtomicInteger seen = new java.util.concurrent.atomic.AtomicInteger();
    private volatile long lastSeen;         // both transient: activity since the extension loaded

    Identity(String id, String name, String colour, String note, String host,
             long createdAt, long updatedAt, LinkedHashMap<String, String> headers) {
        this.id = id;
        this.name = name;
        this.colour = colour == null ? "NONE" : colour;
        this.note = note == null ? "" : note;
        this.host = host == null ? "" : host;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.headers = headers;
    }

    String id() {
        return id;
    }

    String name() {
        return name;
    }

    void setName(String name) {
        this.name = name == null ? "" : name;
    }

    String colour() {
        return colour;
    }

    void setColour(String colour) {
        this.colour = colour == null ? "NONE" : colour;
    }

    String note() {
        return note;
    }

    void setNote(String note) {
        this.note = note == null ? "" : note;
    }

    String host() {
        return host;
    }

    long createdAt() {
        return createdAt;
    }

    long updatedAt() {
        return updatedAt;
    }

    void touch(long now) {
        this.updatedAt = now;
    }

    /** A request wearing this account's session just went by. Counts since the extension loaded. */
    void noteSeen(long now) {
        seen.incrementAndGet();
        lastSeen = now;
    }

    int seenCount() {
        return seen.get();
    }

    long lastSeen() {
        return lastSeen;
    }

    /** The session headers, name → value, in the order they will be sent. A copy. */
    LinkedHashMap<String, String> headers() {
        return new LinkedHashMap<>(headers);
    }

    /** The session headers as {name, value} pairs, to set on a request. */
    List<String[]> headerPairs() {
        List<String[]> out = new ArrayList<>();
        for (Map.Entry<String, String> header : headers.entrySet()) {
            out.add(new String[]{header.getKey(), header.getValue()});
        }
        return out;
    }

    Set<String> identifyingValues() {
        return Credentials.identifyingValues(headers);
    }

    Jwt jwt() {
        return Credentials.jwtIn(headers);
    }

    /**
     * Apply fresh values the server set, cookie by cookie: each name already in this account's
     * Cookie header gets the new value. New cookies the account never had are ignored — they are
     * not part of what identifies it. Returns true when anything changed.
     */
    boolean updateCookies(Map<String, String> fresh, long now) {
        String current = headerValue("Cookie");
        if (current == null || fresh.isEmpty()) {
            return false;
        }
        LinkedHashMap<String, String> cookies = Credentials.cookies(current);
        boolean changed = false;
        for (Map.Entry<String, String> set : fresh.entrySet()) {
            // only a cookie this account already carries, and only a real new value: a cleared
            // cookie (a logout's Set-Cookie) is not a refresh and must not blank what we hold
            if (cookies.containsKey(set.getKey()) && !set.getValue().isEmpty()
                    && !set.getValue().equals(cookies.get(set.getKey()))) {
                cookies.put(set.getKey(), set.getValue());
                changed = true;
            }
        }
        if (changed) {
            setHeader("Cookie", rebuildCookie(cookies));
            updatedAt = now;
        }
        return changed;
    }

    /**
     * A bearer/token header on a request carried a newer token for the same subject: adopt it.
     * Guarded by the JWT subject so a different account's token is never mistaken for a refresh.
     * Cookies are left to {@link #updateCookies}. Returns true when anything changed.
     */
    boolean refreshTokens(Map<String, String> requestSessionHeaders, long now) {
        boolean changed = false;
        for (Map.Entry<String, String> header : requestSessionHeaders.entrySet()) {
            if (header.getKey().equalsIgnoreCase("cookie")) {
                continue;
            }
            String old = headerValue(header.getKey());
            if (old == null || old.equals(header.getValue())) {
                continue;
            }
            Jwt fresh = Jwt.fromHeaderValue(header.getValue());
            Jwt was = Jwt.fromHeaderValue(old);
            if (fresh != null && was != null && !fresh.subject().isEmpty() && fresh.subject().equals(was.subject())) {
                setHeader(header.getKey(), header.getValue());
                changed = true;
            }
        }
        if (changed) {
            updatedAt = now;
        }
        return changed;
    }

    /** Replace every session header with those just captured (a re-login through the proxy). */
    void replaceHeaders(LinkedHashMap<String, String> fresh, long now) {
        headers.clear();
        headers.putAll(fresh);
        updatedAt = now;
    }

    /** Replace a session header's value (same name, case-insensitive), keeping its place. */
    void setHeader(String name, String value) {
        for (String key : headers.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                headers.put(key, value);
                return;
            }
        }
        headers.put(name, value);
    }

    String headerValue(String name) {
        for (Map.Entry<String, String> header : headers.entrySet()) {
            if (header.getKey().equalsIgnoreCase(name)) {
                return header.getValue();
            }
        }
        return null;
    }

    private static String rebuildCookie(Map<String, String> cookies) {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> cookie : cookies.entrySet()) {
            out.append(out.length() > 0 ? "; " : "").append(cookie.getKey()).append('=').append(cookie.getValue());
        }
        return out.toString();
    }

    // ── serialization ─────────────────────────────────────────────────────────
    // One line per identity; free-form text is base64 so no value can hold a separator.

    String serialize() {
        StringBuilder blob = new StringBuilder();
        for (Map.Entry<String, String> header : headers.entrySet()) {
            blob.append(blob.length() > 0 ? "\n" : "").append(enc(header.getKey())).append(' ').append(enc(header.getValue()));
        }
        return String.join("\t", id, enc(name), colour, enc(note), enc(host),
                Long.toString(createdAt), Long.toString(updatedAt), enc(blob.toString()));
    }

    static Identity parse(String line) {
        String[] f = line.split("\t", -1);
        if (f.length < 8) {
            return null;
        }
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        String blob = dec(f[7]);
        if (!blob.isEmpty()) {
            for (String row : blob.split("\n")) {
                int space = row.indexOf(' ');
                if (space > 0) {
                    headers.put(dec(row.substring(0, space)), dec(row.substring(space + 1)));
                }
            }
        }
        try {
            return new Identity(f[0], dec(f[1]), f[2], dec(f[3]), dec(f[4]),
                    Long.parseLong(f[5]), Long.parseLong(f[6]), headers);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String enc(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String dec(String s) {
        try {
            return new String(Base64.getUrlDecoder().decode(s), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return "";
        }
    }
}
