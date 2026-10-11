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

    // ── naming and classification ──────────────────────────────────────────────

    private static final java.util.regex.Pattern BASIC = java.util.regex.Pattern.compile("^Basic\\s+(\\S+)", Pattern.CASE_INSENSITIVE);
    private static final String[] USERNAME_FIELDS = {"username", "user", "userName", "user_name", "email", "login",
            "j_username", "identifier", "account", "loginId"};
    private static final String[] TIERS = {
            "admin|root|superuser|super-user|owner|administrator|sysadmin",
            "staff|manager|moderator|operator|editor|support|developer|maintainer",
            "user|member|customer|subscriber|basic|standard|registered|authenticated",
            "guest|anonymous|anon|visitor|public|readonly|read-only"};
    private static final String[] TIER_NAMES = {"admin", "elevated", "user", "guest"};

    /** The username in a Basic Authorization header ("Basic dXNlcjpwYXNz" → "user"), or "". */
    static String basicUsername(String authValue) {
        if (authValue == null) {
            return "";
        }
        java.util.regex.Matcher m = BASIC.matcher(authValue.trim());
        if (!m.find()) {
            return "";
        }
        try {
            String decoded = new String(java.util.Base64.getDecoder().decode(m.group(1)), java.nio.charset.StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            String user = colon >= 0 ? decoded.substring(0, colon) : decoded;
            return printable(user) ? user.trim() : "";
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    /** A username-like field from a login request body (form or JSON), or "". */
    static String usernameFromBody(String body, String contentType) {
        if (body == null || body.isEmpty() || body.length() > 1_000_000) {
            return "";
        }
        String type = lower(contentType);
        if (type.contains("json") || body.trim().startsWith("{")) {
            try {
                Map<String, Object> doc = Json.object(Json.parse(body));
                if (doc != null) {
                    for (String field : USERNAME_FIELDS) {
                        for (Map.Entry<String, Object> e : doc.entrySet()) {
                            if (e.getKey().equalsIgnoreCase(field) && e.getValue() instanceof String) {
                                String value = ((String) e.getValue()).trim();
                                if (!value.isEmpty() && value.length() <= 100 && printable(value)) {
                                    return value;
                                }
                            }
                        }
                    }
                }
            } catch (Json.Malformed ignored) {
                // not JSON after all: fall through to form parsing
            }
        }
        Map<String, String> form = new LinkedHashMap<>();
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                form.put(urlDecode(pair.substring(0, eq)).trim(), urlDecode(pair.substring(eq + 1)).trim());
            }
        }
        for (String field : USERNAME_FIELDS) {
            for (Map.Entry<String, String> e : form.entrySet()) {
                if (e.getKey().equalsIgnoreCase(field) && !e.getValue().isEmpty() && e.getValue().length() <= 100
                        && printable(e.getValue())) {
                    return e.getValue();
                }
            }
        }
        return "";
    }

    /** The best display name from the session alone: the JWT subject, else a Basic-auth username. "" if neither. */
    static String accountName(Map<String, String> sessionHeaders) {
        Jwt jwt = jwtIn(sessionHeaders);
        if (jwt != null && !jwt.subject().isEmpty()) {
            return jwt.subject();
        }
        for (Map.Entry<String, String> header : sessionHeaders.entrySet()) {
            if (!header.getKey().equalsIgnoreCase("cookie")) {
                String user = basicUsername(header.getValue());
                if (!user.isEmpty()) {
                    return user;
                }
            }
        }
        return "";
    }

    /** A privilege tier from a role/scope string: "admin", "elevated", "user", "guest", or "". */
    static String privilegeTier(String role) {
        String text = lower(role);
        if (text.isEmpty()) {
            return "";
        }
        for (int i = 0; i < TIERS.length; i++) {
            if (Pattern.compile("(?:^|[^a-z])(?:" + TIERS[i] + ")(?:[^a-z]|$)").matcher(text).find()) {
                return TIER_NAMES[i];
            }
        }
        return "";
    }

    /** Higher is more privileged; -1 when unknown. For ordering discovered sessions. */
    static int privilegeRank(String tier) {
        switch (tier) {
            case "admin": return 3;
            case "elevated": return 2;
            case "user": return 1;
            case "guest": return 0;
            default: return -1;
        }
    }

    private static boolean printable(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isISOControl(s.charAt(i))) {
                return false;
            }
        }
        return !s.isEmpty();
    }

    private static String urlDecode(String s) {
        try {
            return java.net.URLDecoder.decode(s, java.nio.charset.StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
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
