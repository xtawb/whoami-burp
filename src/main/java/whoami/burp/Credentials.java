package whoami.burp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * What in a request is the account, rather than the request. These are the
 * headers a browser carries to stay signed in — Cookie, Authorization, CSRF
 * and the various API-key and bearer-token headers — and, within a Cookie, the
 * individual cookies that hold a session.
 *
 * Two jobs: collect those headers so an account can be saved and replayed, and
 * pick out the few values that identify an account, so a later request can be
 * recognised as belonging to it. Everything here is a pure function of the
 * name/value pairs it is given; nothing reaches the network or Burp.
 */
final class Credentials {

    /** Shorter than this, a value is too common to tell one account from another. */
    static final int MIN_VALUE_LEN = 8;

    /** A header whose value is part of who you are signed in as. */
    private static final Pattern SESSION_HEADER = Pattern.compile(
            "^(cookie|authorization)$|csrf|xsrf|token|api[-_]?key|^x-.*(auth|session|account)|session|bearer",
            Pattern.CASE_INSENSITIVE);

    /** A cookie whose name says it holds a session, not a preference or an analytics id. */
    private static final Pattern SESSION_COOKIE = Pattern.compile(
            "sess|sid|auth|token|jwt|sso|csrf|xsrf|remember|login|identity|account|phpsessid|jsessionid"
                    + "|asp\\.?net|laravel|rails|connect",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern SCHEME = Pattern.compile("^(?:Bearer|Token|JWT|Basic|ApiKey)\\s+", Pattern.CASE_INSENSITIVE);

    private Credentials() {
    }

    static boolean carriesSession(String headerName) {
        return headerName != null && SESSION_HEADER.matcher(headerName.trim()).find();
    }

    /**
     * The session-bearing headers among `headers`, name → value, in the order given.
     * `headers` is any sequence of {name, value}; a repeated header keeps its last value.
     */
    static LinkedHashMap<String, String> sessionHeaders(Iterable<String[]> headers) {
        LinkedHashMap<String, String> out = new LinkedHashMap<>();
        for (String[] header : headers) {
            if (header.length >= 2 && header[0] != null && header[1] != null && carriesSession(header[0])
                    && !header[1].isEmpty()) {
                String existing = keyOf(out, header[0]);
                out.remove(existing == null ? header[0] : existing);        // last value wins, original case kept
                out.put(header[0], header[1]);
            }
        }
        return out;
    }

    /** The individual cookies in a Cookie header value, name → value, in order. */
    static LinkedHashMap<String, String> cookies(String cookieHeader) {
        LinkedHashMap<String, String> out = new LinkedHashMap<>();
        if (cookieHeader == null) {
            return out;
        }
        for (String part : cookieHeader.split(";")) {
            int eq = part.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = part.substring(0, eq).trim();
            String value = unquote(part.substring(eq + 1).trim());
            if (!name.isEmpty()) {
                out.put(name, value);
            }
        }
        return out;
    }

    /** A token value without its scheme word ("Bearer abc" → "abc"). */
    static String bareToken(String headerValue) {
        return headerValue == null ? "" : SCHEME.matcher(headerValue.trim()).replaceFirst("");
    }

    /**
     * The values that identify an account among `sessionHeaders`: each session cookie's value,
     * and each bearer / token / key header's value. These are matched, exactly, against later
     * requests — so only values distinctive enough to belong to one account are included.
     */
    static Set<String> identifyingValues(Map<String, String> sessionHeaders) {
        Set<String> out = new LinkedHashSet<>();
        Set<String> allCookieValues = new LinkedHashSet<>();
        for (Map.Entry<String, String> header : sessionHeaders.entrySet()) {
            if (header.getKey().equalsIgnoreCase("cookie")) {
                for (Map.Entry<String, String> cookie : cookies(header.getValue()).entrySet()) {
                    String value = cookie.getValue();
                    if (value.length() >= MIN_VALUE_LEN) {
                        allCookieValues.add(value);
                        if (SESSION_COOKIE.matcher(cookie.getKey()).find()) {
                            out.add(value);
                        }
                    }
                }
            } else {
                String token = bareToken(header.getValue());
                if (token.length() >= MIN_VALUE_LEN) {
                    out.add(token);
                }
            }
        }
        if (out.isEmpty()) {
            // nothing named like a session: fall back to cookie values long enough to be unique by themselves
            for (String value : allCookieValues) {
                if (value.length() >= 2 * MIN_VALUE_LEN) {
                    out.add(value);
                }
            }
        }
        return out;
    }

    /** The first JWT carried by any of these session headers, or null. */
    static Jwt jwtIn(Map<String, String> sessionHeaders) {
        for (Map.Entry<String, String> header : sessionHeaders.entrySet()) {
            Jwt jwt = header.getKey().equalsIgnoreCase("cookie")
                    ? jwtInCookies(header.getValue()) : Jwt.fromHeaderValue(header.getValue());
            if (jwt != null) {
                return jwt;
            }
        }
        return null;
    }

    private static Jwt jwtInCookies(String cookieHeader) {
        for (String value : cookies(cookieHeader).values()) {
            Jwt jwt = Jwt.fromHeaderValue(value);
            if (jwt != null) {
                return jwt;
            }
        }
        return null;
    }

    private static String keyOf(Map<String, String> map, String name) {
        for (String key : map.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                return key;
            }
        }
        return null;
    }

    private static String unquote(String value) {
        return value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")
                ? value.substring(1, value.length() - 1) : value;
    }

    static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    /**
     * The registrable part of a host: roughly its site. "app.acme.io" and "api.acme.io" share
     * "acme.io". An approximation — the last two labels — enough to break a match tie by site,
     * not a public-suffix lookup; it is never the sole reason two requests are judged the same.
     */
    static String registrable(String host) {
        if (host == null || host.isEmpty()) {
            return "";
        }
        host = lower(host.split(":", 2)[0]);
        List<String> labels = split(host, ".");
        int n = labels.size();
        return n <= 2 ? host : labels.get(n - 2) + "." + labels.get(n - 1);
    }

    private static List<String> split(String s, String by) {
        List<String> out = new ArrayList<>();
        int from = 0;
        for (int at = s.indexOf(by); at >= 0; at = s.indexOf(by, from)) {
            out.add(s.substring(from, at));
            from = at + by.length();
        }
        out.add(s.substring(from));
        return out;
    }
}
