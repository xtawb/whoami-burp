package whoami.burp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small JSON reader for one document: the payload of a JWT. Objects become
 * {@code Map<String, Object>}, arrays {@code List<Object>}, strings
 * {@code String}, numbers {@code Double}, and true/false/null their obvious
 * values.
 *
 * The input is untrusted — it comes off the wire — so depth is bounded and
 * every error is the same checked {@link Malformed}, never a stack overflow.
 */
final class Json {

    static final class Malformed extends Exception {
        private static final long serialVersionUID = 1L;

        Malformed(String message) {
            super(message);
        }
    }

    private static final int MAX_DEPTH = 200;

    private final String s;
    private int at;

    private Json(String s) {
        this.s = s;
    }

    static Object parse(String text) throws Malformed {
        Json reader = new Json(text == null ? "" : text);
        reader.blank();
        Object value = reader.value(0);
        reader.blank();
        if (reader.at != reader.s.length()) {
            throw new Malformed("extra data");
        }
        return value;
    }

    /** `value` as an object, or null when it is anything else. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> object(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    private Object value(int depth) throws Malformed {
        if (depth > MAX_DEPTH) {
            throw new Malformed("nested too deeply");
        }
        if (at >= s.length()) {
            throw new Malformed("unexpected end");
        }
        char c = s.charAt(at);
        switch (c) {
            case '{': return object(depth);
            case '[': return array(depth);
            case '"': return string();
            case 't': return word("true", Boolean.TRUE);
            case 'f': return word("false", Boolean.FALSE);
            case 'n': return word("null", null);
            default:  return number();
        }
    }

    private Object word(String word, Object value) throws Malformed {
        if (!s.startsWith(word, at)) {
            throw new Malformed("unexpected token");
        }
        at += word.length();
        return value;
    }

    private Map<String, Object> object(int depth) throws Malformed {
        Map<String, Object> out = new LinkedHashMap<>();
        at++;                                   // {
        blank();
        if (at < s.length() && s.charAt(at) == '}') {
            at++;
            return out;
        }
        while (true) {
            blank();
            if (at >= s.length() || s.charAt(at) != '"') {
                throw new Malformed("expected a property name");
            }
            String key = string();
            blank();
            expect(':');
            blank();
            out.put(key, value(depth + 1));
            blank();
            if (at >= s.length()) {
                throw new Malformed("unterminated object");
            }
            char c = s.charAt(at++);
            if (c == '}') {
                return out;
            }
            if (c != ',') {
                throw new Malformed("expected ',' or '}'");
            }
        }
    }

    private List<Object> array(int depth) throws Malformed {
        List<Object> out = new ArrayList<>();
        at++;                                   // [
        blank();
        if (at < s.length() && s.charAt(at) == ']') {
            at++;
            return out;
        }
        while (true) {
            blank();
            out.add(value(depth + 1));
            blank();
            if (at >= s.length()) {
                throw new Malformed("unterminated array");
            }
            char c = s.charAt(at++);
            if (c == ']') {
                return out;
            }
            if (c != ',') {
                throw new Malformed("expected ',' or ']'");
            }
        }
    }

    private void expect(char c) throws Malformed {
        if (at >= s.length() || s.charAt(at++) != c) {
            throw new Malformed("expected '" + c + "'");
        }
    }

    private String string() throws Malformed {
        at++;                                   // opening quote
        StringBuilder out = new StringBuilder();
        while (at < s.length()) {
            char c = s.charAt(at++);
            if (c == '"') {
                return out.toString();
            }
            if (c == '\\') {
                if (at >= s.length()) {
                    break;
                }
                char e = s.charAt(at++);
                switch (e) {
                    case '"': out.append('"'); break;
                    case '\\': out.append('\\'); break;
                    case '/': out.append('/'); break;
                    case 'b': out.append('\b'); break;
                    case 'f': out.append('\f'); break;
                    case 'n': out.append('\n'); break;
                    case 'r': out.append('\r'); break;
                    case 't': out.append('\t'); break;
                    case 'u':
                        if (at + 4 > s.length()) {
                            throw new Malformed("bad \\u escape");
                        }
                        try {
                            out.append((char) Integer.parseInt(s.substring(at, at + 4), 16));
                        } catch (NumberFormatException nfe) {
                            throw new Malformed("bad \\u escape");
                        }
                        at += 4;
                        break;
                    default:
                        throw new Malformed("bad escape");
                }
            } else {
                out.append(c);
            }
        }
        throw new Malformed("unterminated string");
    }

    private Double number() throws Malformed {
        int start = at;
        while (at < s.length() && "+-0123456789.eE".indexOf(s.charAt(at)) >= 0) {
            at++;
        }
        try {
            return Double.parseDouble(s.substring(start, at));
        } catch (NumberFormatException e) {
            throw new Malformed("not a value");
        }
    }

    private void blank() {
        while (at < s.length()) {
            char c = s.charAt(at);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                return;
            }
            at++;
        }
    }
}
