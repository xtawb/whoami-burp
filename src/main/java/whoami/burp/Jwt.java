package whoami.burp;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * What a JSON Web Token says about itself — read, never checked. A JWT is three
 * base64url parts; this decodes the middle one (the claims) and offers the few
 * that name an account: who it is for ({@code sub}), what it may do ({@code
 * role} / {@code scope} …), and when it stops working ({@code exp}).
 *
 * The signature is ignored. Nothing here proves a token is genuine or current;
 * it only reads what the token asserts, so a label can be put on it.
 */
final class Jwt {

    /** A compact JWS: three dot-separated base64url parts, the middle one JSON. */
    private static final java.util.regex.Pattern SHAPE =
            java.util.regex.Pattern.compile("eyJ[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]{0,}");

    private final Map<String, Object> claims;

    private Jwt(Map<String, Object> claims) {
        this.claims = claims;
    }

    /** Read the token's claims, or null when `token` is not a JWT this can open. */
    static Jwt read(String token) {
        if (token == null) {
            return null;
        }
        token = token.trim();
        int dot = token.indexOf('.');
        int dot2 = dot < 0 ? -1 : token.indexOf('.', dot + 1);
        if (dot < 0 || dot2 < 0) {
            return null;
        }
        String payload = token.substring(dot + 1, dot2);
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(pad(payload));
            Map<String, Object> claims = Json.object(Json.parse(new String(bytes, StandardCharsets.UTF_8)));
            return claims == null ? null : new Jwt(claims);
        } catch (RuntimeException | Json.Malformed e) {
            return null;                        // base64 that is not, or JSON that is not: not a JWT we can use
        }
    }

    /** The first JWT found in a header value (a bare token, or after "Bearer "), or null. */
    static Jwt fromHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        java.util.regex.Matcher m = SHAPE.matcher(value);
        return m.find() ? read(m.group()) : null;
    }

    private static String pad(String base64url) {
        int remainder = base64url.length() % 4;
        return remainder == 0 ? base64url : base64url + "====".substring(remainder);
    }

    /** A claim as text: a string or number as itself, an array as its values joined by ", ". "" when absent. */
    String claim(String... names) {
        for (String name : names) {
            Object value = claims.get(name);
            if (value != null) {
                return asText(value);
            }
        }
        return "";
    }

    /** Who the token is for: the first of the usual subject claims that is set. */
    String subject() {
        return claim("sub", "user_id", "userId", "uid", "email", "preferred_username", "name");
    }

    /** What it grants: the first of the usual authority claims that is set. */
    String role() {
        return claim("role", "roles", "scope", "scopes", "authorities", "permissions", "groups");
    }

    String issuer() {
        return claim("iss");
    }

    /** Seconds since the epoch at which the token expires, or 0 when it says nothing. */
    long expiresAt() {
        Object exp = claims.get("exp");
        return exp instanceof Double ? (long) (double) (Double) exp : 0L;
    }

    boolean hasExpiry() {
        return expiresAt() > 0;
    }

    boolean isExpired(long nowSeconds) {
        return hasExpiry() && expiresAt() <= nowSeconds;
    }

    private static String asText(Object value) {
        if (value instanceof String) {
            return (String) value;
        }
        if (value instanceof Double) {
            double d = (Double) value;
            return d == Math.rint(d) && !Double.isInfinite(d) ? Long.toString((long) d) : Double.toString(d);
        }
        if (value instanceof List) {
            StringBuilder out = new StringBuilder();
            for (Object item : (List<?>) value) {
                if (item instanceof String || item instanceof Double) {
                    out.append(out.length() > 0 ? ", " : "").append(asText(item));
                }
            }
            return out.toString();
        }
        return "";
    }
}
