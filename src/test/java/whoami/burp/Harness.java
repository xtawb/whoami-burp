package whoami.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

/**
 * Drives the extension and its pieces without a Burp process: the pure logic
 * (JWT, credentials, identities, the store) directly, and the extension itself
 * against {@link MockBurp}. One program, failures stop it.
 */
public final class Harness {

    private static int checks;

    private static void check(boolean ok, String what) {
        checks++;
        if (!ok) {
            System.err.println("FAILED: " + what);
            System.exit(1);
        }
    }

    // a JWT with no real signature: three base64url parts, the middle the claims
    private static String jwt(String payloadJson) {
        String header = b64url("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        return header + "." + b64url(payloadJson) + ".sig";
    }

    private static String b64url(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static List<String[]> hdrs(String... nameValue) {
        List<String[]> out = new ArrayList<>();
        for (int i = 0; i + 1 < nameValue.length; i += 2) {
            out.add(new String[]{nameValue[i], nameValue[i + 1]});
        }
        return out;
    }

    public static void main(String[] args) throws Exception {
        jwtTests();
        credentialTests();
        identityTests();
        storeTests();
        hostileInput();
        extensionAgainstMockedBurp();
        System.out.println("harness: " + checks + " checks passed");
        System.exit(0);
    }

    // ── input written to break a parser ───────────────────────────────────────
    // Headers and Set-Cookie come off the wire. Reading them must stay quick and never throw.

    private static void hostileInput() {
        long began = System.nanoTime();

        StringBuilder deep = new StringBuilder();
        for (int i = 0; i < 100_000; i++) {
            deep.append('[');
        }
        check(Jwt.read(jwt(deep.toString())) == null, "a JWT whose claims nest without end is refused, not followed");

        String huge = "x".repeat(2_000_000);
        check(Jwt.read(jwt("{\"sub\":\"" + huge + "\"}")) != null || true, "a megabyte of claims is read without hanging");
        check(Jwt.fromHeaderValue("Bearer " + huge) == null, "a megabyte that is not a JWT is dismissed");

        StringBuilder cookie = new StringBuilder();
        for (int i = 0; i < 50_000; i++) {
            cookie.append("c").append(i).append("=").append("v").append(i).append("; ");
        }
        Map<String, String> many = Credentials.cookies(cookie.toString());
        check(many.size() == 50_000, "fifty thousand cookies are parsed: " + many.size());
        check(!Credentials.identifyingValues(Credentials.sessionHeaders(
                hdrs("Cookie", cookie.toString()))).isEmpty() || true, "identifying values over a huge cookie header return");

        check(Identity.parse("garbage") == null && Identity.parse("") == null, "a line that is not an identity parses to null");
        new Store().load("garbage\n\nmore garbage");       // must not throw

        long ms = (System.nanoTime() - began) / 1_000_000;
        check(ms < 10_000, "hostile input is handled quickly (" + ms + " ms)");
        System.out.println("hostile input: ok (" + ms + " ms)");
    }

    // ── JWT ──────────────────────────────────────────────────────────────────

    private static void jwtTests() {
        String token = jwt("{\"sub\":\"alice@acme.io\",\"role\":[\"admin\",\"user\"],\"exp\":4102444800}");
        Jwt j = Jwt.read(token);
        check(j != null, "a JWT is read");
        check(j.subject().equals("alice@acme.io"), "subject: " + j.subject());
        check(j.role().equals("admin, user"), "an array claim is joined: " + j.role());
        check(j.expiresAt() == 4102444800L && j.hasExpiry(), "expiry is read as a number");
        check(!j.isExpired(1000) && j.isExpired(4102444801L), "expiry is compared to now");

        Jwt expired = Jwt.read(jwt("{\"sub\":\"bob\",\"exp\":100}"));
        check(expired.isExpired(System.currentTimeMillis() / 1000), "an old token is expired");

        check(Jwt.fromHeaderValue("Bearer " + token) != null, "a bearer header's token is found");
        check(Jwt.fromHeaderValue("sessionJwt=" + token + "; other=1") != null, "a token inside a cookie value is found");
        check(Jwt.read("not.a.jwt") == null && Jwt.read("one-part") == null && Jwt.read(null) == null,
                "what is not a JWT reads as null");
        check(Jwt.read(jwt("{bad json")) == null, "a token whose claims are not JSON reads as null");
        check(Jwt.fromHeaderValue("Bearer abcdef") == null, "a short opaque token is not taken for a JWT");
    }

    // ── credentials ────────────────────────────────────────────────────────

    private static void credentialTests() {
        check(Credentials.carriesSession("Cookie") && Credentials.carriesSession("authorization")
                && Credentials.carriesSession("X-CSRF-Token") && Credentials.carriesSession("X-Api-Key")
                && Credentials.carriesSession("X-Xsrf-Token"), "session headers are recognised");
        check(!Credentials.carriesSession("Accept") && !Credentials.carriesSession("User-Agent")
                && !Credentials.carriesSession("Content-Type"), "ordinary headers are not");

        LinkedHashMap<String, String> session = Credentials.sessionHeaders(hdrs(
                "Host", "acme.io", "Cookie", "sid=ABCDEFGH12; _ga=TRACK1234567",
                "Authorization", "Bearer TOKEN12345678", "Accept", "*/*"));
        check(session.size() == 2 && session.containsKey("Cookie") && session.containsKey("Authorization"),
                "only session headers are kept: " + session.keySet());

        Map<String, String> cookies = Credentials.cookies("sid=ABCDEFGH12; _ga=TRACK1234567; pref=\"dark\"");
        check(cookies.size() == 3 && cookies.get("sid").equals("ABCDEFGH12") && cookies.get("pref").equals("dark"),
                "cookies are parsed, quotes stripped: " + cookies);

        Set<String> values = Credentials.identifyingValues(session);
        check(values.contains("ABCDEFGH12") && values.contains("TOKEN12345678") && !values.contains("TRACK1234567"),
                "a session cookie and a bearer token identify; an analytics cookie does not: " + values);

        Set<String> fallback = Credentials.identifyingValues(Credentials.sessionHeaders(
                hdrs("Cookie", "theme=0123456789ABCDEF; n=short")));
        check(fallback.contains("0123456789ABCDEF") && !fallback.contains("short"),
                "with nothing named like a session, a long cookie value stands in: " + fallback);

        check(Credentials.bareToken("Bearer abc.def.ghi").equals("abc.def.ghi")
                && Credentials.bareToken("abc").equals("abc"), "a scheme word is stripped from a token");
    }

    // ── identity ─────────────────────────────────────────────────────────────

    private static void identityTests() {
        long t = 1_000_000L;
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        headers.put("Cookie", "sid=ABCDEFGH12; csrf=CSRF567890");
        headers.put("X-CSRF-Token", "CSRF567890");
        Identity a = new Identity("id-1", "Admin · عميل", "CYAN", "a note", "acme.io", t, t, headers);

        Identity back = Identity.parse(a.serialize());
        check(back != null && back.name().equals("Admin · عميل") && back.colour().equals("CYAN")
                && back.note().equals("a note") && back.host().equals("acme.io"), "an identity round-trips through text");
        check(back.headers().get("Cookie").equals("sid=ABCDEFGH12; csrf=CSRF567890"), "its headers survive verbatim");
        check(back.serialize().indexOf('\n') < 0 && back.serialize().indexOf('\t') == a.serialize().indexOf('\t'),
                "a serialized identity is one line");

        LinkedHashMap<String, String> fresh = new LinkedHashMap<>();
        fresh.put("sid", "NEW9999999");
        fresh.put("unrelated", "ZZZZZZZZ");                 // a cookie the account never had
        fresh.put("csrf", "");                              // a deletion
        check(a.updateCookies(fresh, t + 1) && a.headerValue("Cookie").equals("sid=NEW9999999; csrf=CSRF567890"),
                "a known cookie is refreshed; an unknown one and a deletion are ignored: " + a.headerValue("Cookie"));
        check(a.updatedAt() == t + 1 && !a.updateCookies(new LinkedHashMap<>(), t + 2), "an empty refresh changes nothing");

        // a bearer token rotates, same subject → adopted; a different subject → refused
        LinkedHashMap<String, String> withJwt = new LinkedHashMap<>();
        withJwt.put("Authorization", "Bearer " + jwt("{\"sub\":\"alice\",\"exp\":1}"));
        Identity b = new Identity("id-2", "Alice", "GREEN", "", "acme.io", t, t, withJwt);
        String rotated = "Bearer " + jwt("{\"sub\":\"alice\",\"exp\":2}");
        check(b.refreshTokens(Map.of("Authorization", rotated), t + 5) && b.headerValue("Authorization").equals(rotated),
                "a rotated token for the same subject is adopted");
        String other = "Bearer " + jwt("{\"sub\":\"mallory\",\"exp\":9}");
        check(!b.refreshTokens(Map.of("Authorization", other), t + 6)
                && b.headerValue("Authorization").equals(rotated), "a token for another subject is refused");

        check(a.jwt() == null && b.jwt() != null && b.jwt().subject().equals("alice"), "an identity reads its own JWT");

        LinkedHashMap<String, String> replacement = new LinkedHashMap<>();
        replacement.put("Cookie", "sid=REPLACED99");
        b.replaceHeaders(replacement, t + 7);
        check(b.headers().size() == 1 && b.headerValue("Cookie").equals("sid=REPLACED99"), "headers can be replaced wholesale");
    }

    // ── store ────────────────────────────────────────────────────────────────

    private static void storeTests() {
        Store store = new Store();
        int[] changes = {0};
        store.setListener(() -> changes[0]++);

        check(store.nextColour().equals("CYAN"), "the first account is cyan");
        Identity a = store.create("A", store.nextColour(), "acme.io", session("sidAAAAAAAA"), 10);
        store.add(a);
        check(store.nextColour().equals("GREEN"), "the second account is a different colour");
        Identity b = store.create("B", store.nextColour(), "acme.io", session("sidBBBBBBBB"), 20);
        store.add(b);
        check(store.size() == 2 && changes[0] == 2, "accounts are added and the listener hears it");

        check(store.match(sessionMap("sidAAAAAAAA")) == a, "a request with A's cookie matches A");
        check(store.match(sessionMap("sidBBBBBBBB")) == b, "a request with B's cookie matches B");
        check(store.match(sessionMap("nobodyknows99")) == null, "an unknown session matches nobody");

        // a shared value: the more recently used account wins the tie
        Identity c = store.create("C", "PINK", "acme.io", session("SHAREDVALUE1"), 30);
        Identity d = store.create("D", "BLUE", "acme.io", session("SHAREDVALUE1"), 40);
        store.add(c);
        store.add(d);
        check(store.match(sessionMap("SHAREDVALUE1")) == d, "a tie goes to the most recently used account");

        String blob = store.serialize();
        Store loaded = new Store();
        loaded.load(blob);
        check(loaded.size() == 4 && loaded.match(sessionMap("sidAAAAAAAA")).name().equals("A"),
                "the whole store round-trips and still matches");

        store.remove(a.id());
        check(store.size() == 3 && store.get(a.id()) == null, "an account can be removed");
        store.clear();
        check(store.size() == 0, "the store can be cleared");
    }

    private static LinkedHashMap<String, String> session(String sidValue) {
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        headers.put("Cookie", "sid=" + sidValue);
        return headers;
    }

    private static Map<String, String> sessionMap(String sidValue) {
        return session(sidValue);
    }

    // ── the extension against a mocked Burp ───────────────────────────────────

    private static void extensionAgainstMockedBurp() throws Exception {
        MockBurp burp = new MockBurp();

        // an account saved in an earlier session, in the project file
        Store seed = new Store();
        seed.add(seed.create("Admin", "CYAN", "acme.io", session("ADMINSID123"), 100));
        burp.projectData.put("whoami.accounts.v1", seed.serialize());

        WhoAmIExtension ext = new WhoAmIExtension();
        ext.initialize(burp.api());
        check(burp.suiteTab == ext.tab, "the extension registers its tab");
        check(ext.store.size() == 1 && ext.store.all().get(0).name().equals("Admin"),
                "accounts are loaded from the project file");
        String adminId = ext.store.all().get(0).id();

        // a request carrying the admin session is coloured and labelled
        Annotations annotations = MockBurp.annotations(null);
        InterceptedRequest adminRequest = MockBurp.interceptedRequest("https://acme.io/admin", "GET",
                hdrs("Host", "acme.io", "Cookie", "sid=ADMINSID123; _ga=XYZ"), annotations);
        ext.handleRequestReceived(adminRequest);
        check(annotations.highlightColor() == HighlightColor.CYAN, "a recognised request is coloured: " + annotations.highlightColor());
        check("Admin".equals(annotations.notes()), "…and labelled with the account name: " + annotations.notes());

        // a comment the user already wrote is kept
        Annotations withNote = MockBurp.annotations("look here");
        ext.handleRequestReceived(MockBurp.interceptedRequest("https://acme.io/x", "GET",
                hdrs("Cookie", "sid=ADMINSID123"), withNote));
        check(withNote.highlightColor() == HighlightColor.CYAN && "look here".equals(withNote.notes()),
                "an existing comment is not overwritten");

        // a request with no known session is left alone
        Annotations plain = MockBurp.annotations(null);
        ext.handleRequestReceived(MockBurp.interceptedRequest("https://acme.io/pub", "GET",
                hdrs("Accept", "*/*"), plain));
        check(plain.highlightColor() == HighlightColor.NONE && plain.notes() == null, "an anonymous request is not touched");

        // the server rotates the admin's session cookie: the stored account follows
        HttpRequest initiating = MockBurp.request("https://acme.io/login", "POST", hdrs("Cookie", "sid=ADMINSID123"));
        List<Cookie> setCookies = List.of(MockBurp.cookie("sid", "ADMINSID999"));
        ext.handleResponseReceived(MockBurp.interceptedResponse(initiating, setCookies));
        check(ext.store.get(adminId).headerValue("Cookie").contains("ADMINSID999"), "a Set-Cookie refreshes the stored account");
        check(reloaded(burp).get(adminId).headerValue("Cookie").contains("ADMINSID999"),
                "the refreshed account is written back to the project file");

        // the context menu: save / update offered for a request with a session, send-as always
        HttpRequest withSession = MockBurp.request("https://acme.io/api", "GET", hdrs("Cookie", "sid=ADMINSID999"));
        List<java.awt.Component> items = ext.provideMenuItems(MockBurp.contextMenuEvent(withSession));
        check(hasItem(items, "WhoAmI: Save as new account"), "save is offered for a request with a session");
        check(hasItem(items, "WhoAmI: Update \"Admin\" from this request"), "update is offered when the request matches an account");
        JMenu sendAs = sendAsMenu(items);
        check(sendAs != null, "a \"Send as\" menu is offered");

        // send a session-less request AS the admin → Repeater gets the admin's cookie
        HttpRequest target = MockBurp.request("https://acme.io/thing", "GET", hdrs("Accept", "*/*"));
        List<java.awt.Component> onTarget = ext.provideMenuItems(MockBurp.contextMenuEvent(target));
        clickSendAs(onTarget, "Admin");
        HttpRequest sent = lastRepeaterRequest(burp);
        check(sent != null && sent.hasHeader("Cookie") && sent.headerValue("Cookie").contains("ADMINSID999"),
                "\"Send as Admin\" gives Repeater the admin's session");
        check(burp.repeater.get(burp.repeater.size() - 1)[1].equals("WhoAmI: Admin"), "…in a named Repeater tab");

        // send a request that HAS a session as "no session" → the session is stripped
        clickSendAs(ext.provideMenuItems(MockBurp.contextMenuEvent(withSession)), "(no session)");
        HttpRequest stripped = lastRepeaterRequest(burp);
        check(!stripped.hasHeader("Cookie"), "\"no session\" strips the session headers");

        // tab actions: rename, recolour, delete — reflected and persisted
        ext.rename(adminId, "Administrator");
        ext.recolour(adminId, "RED");
        check(ext.store.get(adminId).name().equals("Administrator") && ext.store.get(adminId).colour().equals("RED"),
                "rename and recolour take effect");
        check(reloaded(burp).get(adminId).name().equals("Administrator") && reloaded(burp).get(adminId).colour().equals("RED"),
                "…and are written to the project file");

        // turn remembering off: nothing of ours stays on disk, the account stays in memory
        ext.tab.rememberInProject.setSelected(false);
        ext.rememberInProjectChanged(false);
        check(!burp.projectData.containsKey("whoami.accounts.v1"), "turning off \"remember\" clears the project file");
        ext.rename(adminId, "Still Here");
        check(ext.store.get(adminId).name().equals("Still Here") && !burp.projectData.containsKey("whoami.accounts.v1"),
                "an in-memory change is not written once remembering is off");

        ext.clearAll();
        check(ext.store.size() == 0, "clear empties the store");

        System.out.println("extension against mocked Burp: ok");
    }

    /** The store as it would come back from the project file: proof that a change was persisted. */
    private static Store reloaded(MockBurp burp) {
        Store store = new Store();
        store.load(burp.projectData.get("whoami.accounts.v1"));
        return store;
    }

    private static boolean hasItem(List<java.awt.Component> items, String text) {
        for (java.awt.Component c : items) {
            if (c instanceof JMenuItem && text.equals(((JMenuItem) c).getText())) {
                return true;
            }
        }
        return false;
    }

    private static JMenu sendAsMenu(List<java.awt.Component> items) {
        for (java.awt.Component c : items) {
            if (c instanceof JMenu && ((JMenu) c).getText().equals("WhoAmI: Send as")) {
                return (JMenu) c;
            }
        }
        return null;
    }

    private static void clickSendAs(List<java.awt.Component> items, String name) throws Exception {
        JMenu menu = sendAsMenu(items);
        check(menu != null, "send-as menu present for clicking");
        for (int i = 0; i < menu.getItemCount(); i++) {
            JMenuItem item = menu.getItem(i);
            if (item != null && item.getText().equals(name)) {
                JMenuItem target = item;
                SwingUtilities.invokeAndWait(target::doClick);
                return;
            }
        }
        check(false, "send-as item \"" + name + "\" present");
    }

    private static HttpRequest lastRepeaterRequest(MockBurp burp) {
        return burp.repeater.isEmpty() ? null : (HttpRequest) burp.repeater.get(burp.repeater.size() - 1)[0];
    }
}
