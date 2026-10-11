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
        smarterRecognitionTests();
        discoveryTests();
        namingAndClassificationTests();
        hostileInput();
        extensionAgainstMockedBurp();
        sessionHandlingTests();
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

        // a rotation is adopted only with a stable anchor: otherwise a different login would steal the account
        LinkedHashMap<String, String> anchored = new LinkedHashMap<>();
        anchored.put("Cookie", "sid=OLDSID1234");
        anchored.put("Authorization", "Bearer " + jwt("{\"sub\":\"alice\",\"exp\":1}"));
        Identity withAnchor = new Identity("id-3", "Alice", "CYAN", "", "acme.io", t, t, anchored);
        java.util.Set<String> anchorReq = Credentials.identifyingValues(Credentials.sessionHeaders(
                hdrs("Cookie", "sid=OLDSID1234", "Authorization", anchored.get("Authorization"))));
        check(withAnchor.isRotationAnchored(Map.of("sid", "NEWSID9999"), anchorReq),
                "a cookie rotation with a stable anchor is a real rotation");

        LinkedHashMap<String, String> single = new LinkedHashMap<>();
        single.put("Cookie", "sid=OLDSID1234");
        Identity soloCookie = new Identity("id-4", "Solo", "CYAN", "", "acme.io", t, t, single);
        java.util.Set<String> soloReq = Credentials.identifyingValues(Credentials.sessionHeaders(hdrs("Cookie", "sid=OLDSID1234")));
        check(!soloCookie.isRotationAnchored(Map.of("sid", "NEWSID9999"), soloReq),
                "a new value on a single-cookie session is not treated as a rotation");
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

    // ── smarter recognition: state, session lineage, host-aware matching ──────

    private static void smarterRecognitionTests() {
        check(Credentials.registrable("app.acme.io").equals("acme.io")
                && Credentials.registrable("acme.io").equals("acme.io")
                && Credentials.registrable("localhost").equals("localhost")
                && Credentials.registrable("a.b.c.co").equals("c.co"), "the registrable site of a host is found");

        // account state
        long t = 1000;
        Identity idle = new Identity("s1", "A", "CYAN", "", "acme.io", t, t, sessionHeaders("sid=IDLEAAAAAA"));
        check(idle.state(5000).equals("idle"), "an account not seen since load is idle");
        idle.noteSeen(6000_000L);
        check(idle.state(5000).equals("active"), "an account matched since load is active");
        LinkedHashMap<String, String> jwtHeaders = new LinkedHashMap<>();
        jwtHeaders.put("Authorization", "Bearer " + jwt("{\"sub\":\"x\",\"exp\":100}"));
        Identity expired = new Identity("s2", "B", "CYAN", "", "acme.io", t, t, jwtHeaders);
        expired.noteSeen(9_000_000L);
        check(expired.state(System.currentTimeMillis() / 1000).equals("expired"), "an expired token shows as expired, seen or not");

        // session lineage: a value rotated away from still attributes old traffic, but a current value wins
        Store store = new Store();
        Identity acc = store.create("User", "CYAN", "acme.io", sessionHeaders("sid=OLDVALUE11"), t);
        store.add(acc);
        acc.updateCookies(Map.of("sid", "NEWVALUE22"), t + 1);
        check(acc.pastValues().contains("OLDVALUE11"), "a rotated value is remembered");
        check(store.match(sessionMap("NEWVALUE22")) == acc, "the current value matches");
        check(store.match(sessionMap("OLDVALUE11")) == acc, "a request still carrying the old value is attributed to the account");
        Identity fresh = store.create("Newcomer", "GREEN", "acme.io", sessionHeaders("OLDVALUE11"), t + 5);
        store.add(fresh);
        check(store.match(sessionMap("OLDVALUE11")) == fresh, "but an account currently using that value wins over the lineage");

        // host breaks a tie: the same value on two sites goes to the account from the request's site
        Store two = new Store();
        Identity here = two.create("Here", "CYAN", "app.acme.io", sessionHeaders("sid=SHARED123456"), t);
        Identity there = two.create("There", "GREEN", "app.other.io", sessionHeaders("sid=SHARED123456"), t);
        two.add(here);
        two.add(there);
        check(two.match(sessionMap("SHARED123456"), "www.acme.io") == here, "a tie goes to the account on the request's site (acme)");
        check(two.match(sessionMap("SHARED123456"), "api.other.io") == there, "…and to the other on the other site");
    }

    private static LinkedHashMap<String, String> sessionHeaders(String cookie) {
        LinkedHashMap<String, String> h = new LinkedHashMap<>();
        h.put("Cookie", cookie.contains("=") ? cookie : "sid=" + cookie);
        return h;
    }

    // ── discovery ────────────────────────────────────────────────────────────

    private static Discovery.Request req(String host, String path, String... headerNameValues) {
        return new Discovery.Request(host, path, Credentials.sessionHeaders(hdrs(headerNameValues)));
    }

    private static void discoveryTests() {
        String alice = "Bearer " + jwt("{\"sub\":\"alice\",\"exp\":1}");
        String aliceLater = "Bearer " + jwt("{\"sub\":\"alice\",\"exp\":2}");
        List<Discovery.Request> history = List.of(
                req("acme.io", "/a", "Cookie", "sid=AAAAAAAA10"),
                req("acme.io", "/b", "Cookie", "sid=AAAAAAAA10", "Authorization", alice),  // richest for alice
                req("acme.io", "/c", "Cookie", "sid=ROTATED999", "Authorization", aliceLater),  // cookie rotated, same subject
                req("acme.io", "/d", "Cookie", "sid=BBBBBBBB20"),                         // a second account
                req("acme.io", "/pub"));                                                  // anonymous
        List<Discovery.Candidate> found = Discovery.cluster(history);
        check(found.size() == 2, "two accounts are found on one site, the anonymous request ignored: " + found.size());
        check(found.get(0).requests == 3 && found.get(0).subject.equals("alice"),
                "cookie rotation does not split an account: " + found.get(0).requests);
        check(found.get(0).headers.containsKey("Authorization") && found.get(0).headers.containsKey("Cookie"),
                "the richest session is the candidate's, ready to save");
        check(found.get(1).requests == 1 && found.get(1).subject.isEmpty(), "the second account is separate");
        check(Discovery.cluster(List.of(req("x", "/", "Accept", "*/*"))).isEmpty(), "no session means no candidate");
    }

    // ── smarter naming and privilege classification ──────────────────────────

    private static void namingAndClassificationTests() {
        // Basic auth username (base64 of "alice:secret" built at runtime, no literal credential)
        String basic = "Basic " + Base64.getEncoder().encodeToString("alice:s3cret!".getBytes(StandardCharsets.UTF_8));
        check(Credentials.basicUsername(basic).equals("alice"), "a Basic-auth username is read: " + Credentials.basicUsername(basic));
        check(Credentials.basicUsername("Bearer x").isEmpty() && Credentials.basicUsername("Basic !!notbase64")
                .isEmpty(), "a non-Basic or malformed header yields no username");

        check(Credentials.usernameFromBody("username=bob&password=p", "application/x-www-form-urlencoded").equals("bob"),
                "a form login body gives the username");
        check(Credentials.usernameFromBody("{\"email\":\"carol@x.io\",\"pass\":\"p\"}", "application/json").equals("carol@x.io"),
                "a JSON login body gives the username");
        check(Credentials.usernameFromBody("{\"token\":\"abc\"}", "application/json").isEmpty(), "a body with no username gives none");

        LinkedHashMap<String, String> basicSession = new LinkedHashMap<>();
        basicSession.put("Authorization", basic);
        check(Credentials.accountName(basicSession).equals("alice"), "an account with Basic auth is named by its user");
        LinkedHashMap<String, String> jwtSession = new LinkedHashMap<>();
        jwtSession.put("Authorization", "Bearer " + jwt("{\"sub\":\"dave@x.io\"}"));
        check(Credentials.accountName(jwtSession).equals("dave@x.io"), "a JWT account is named by its subject");

        check(Credentials.privilegeTier("administrator").equals("admin")
                && Credentials.privilegeTier("ROLE_ADMIN").equals("admin")
                && Credentials.privilegeTier("support agent").equals("elevated")
                && Credentials.privilegeTier("member").equals("user")
                && Credentials.privilegeTier("anonymous").equals("guest")
                && Credentials.privilegeTier("wizard").isEmpty(), "a role is placed in a privilege tier");
        check(Credentials.privilegeRank("admin") > Credentials.privilegeRank("user")
                && Credentials.privilegeRank("user") > Credentials.privilegeRank("guest")
                && Credentials.privilegeRank("") < 0, "tiers are ranked, unknown lowest");
    }

    // ── the extension against a mocked Burp ───────────────────────────────────

    private static void extensionAgainstMockedBurp() throws Exception {
        MockBurp burp = new MockBurp();

        // an account saved in an earlier session, in the project file (a cookie plus a bearer token)
        Store seed = new Store();
        LinkedHashMap<String, String> adminHeaders = new LinkedHashMap<>();
        adminHeaders.put("Cookie", "sid=ADMINSID123");
        adminHeaders.put("Authorization", "Bearer " + jwt("{\"sub\":\"admin\",\"exp\":4102444800}"));
        seed.add(seed.create("Admin", "CYAN", "acme.io", adminHeaders, 100));
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

        check(ext.store.get(adminId).seenCount() >= 2, "matched requests are counted as seen: " + ext.store.get(adminId).seenCount());

        // the server rotates the admin's cookie on a request that still carries the admin's bearer
        // token (the stable anchor): the stored account follows
        HttpRequest initiating = MockBurp.request("https://acme.io/thing", "GET",
                hdrs("Cookie", "sid=ADMINSID123", "Authorization", adminHeaders.get("Authorization")));
        List<Cookie> setCookies = List.of(MockBurp.cookie("sid", "ADMINSID999"));
        ext.handleResponseReceived(MockBurp.interceptedResponse(initiating, setCookies));
        check(ext.store.get(adminId).headerValue("Cookie").contains("ADMINSID999"), "a Set-Cookie refreshes the stored account");
        check(reloaded(burp).get(adminId).headerValue("Cookie").contains("ADMINSID999"),
                "the refreshed account is written back to the project file");

        // the reported bug: log out of one account, log in as another on the same cookie name.
        // the first account must not swallow the second's session, and the second must not show as the first.
        Identity user = ext.store.create("User one", "GREEN", "acme.io", session("USERONE1111"), 200);
        ext.store.add(user);
        HttpRequest loginAsTwo = MockBurp.request("https://acme.io/login", "POST", hdrs("Cookie", "sid=USERONE1111"));
        ext.handleResponseReceived(MockBurp.interceptedResponse(loginAsTwo, List.of(MockBurp.cookie("sid", "USERTWO2222"))));
        check(ext.store.get(user.id()).headerValue("Cookie").contains("USERONE1111")
                && !ext.store.get(user.id()).headerValue("Cookie").contains("USERTWO2222"),
                "a different login does not overwrite the first account's cookie: " + ext.store.get(user.id()).headerValue("Cookie"));
        Annotations asTwo = MockBurp.annotations(null);
        ext.handleRequestReceived(MockBurp.interceptedRequest("https://acme.io/home", "GET", hdrs("Cookie", "sid=USERTWO2222"), asTwo));
        check(asTwo.highlightColor() == HighlightColor.NONE && asTwo.notes() == null,
                "the second account's own traffic is not coloured as the first");
        ext.store.remove(user.id());

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

        // discovery end to end: two sessions in the history become two accounts, then are known
        burp.history.add(MockBurp.request("https://shop.acme.io/a", "GET", hdrs("Cookie", "sid=USERAAAA1111")));
        burp.history.add(MockBurp.request("https://shop.acme.io/b", "GET",
                hdrs("Cookie", "sid=USERAAAA1111", "Authorization", "Bearer " + jwt("{\"sub\":\"u1\",\"exp\":9}"))));
        burp.history.add(MockBurp.request("https://shop.acme.io/c", "GET", hdrs("Cookie", "sid=USERBBBB2222")));
        burp.history.add(MockBurp.request("https://shop.acme.io/pub", "GET", hdrs("Accept", "*/*")));
        ext.scanHistory();
        waitUntil(() -> ext.tab.discoveredCount() == 2, "the history scan finds the two sessions");
        for (WhoAmITab.Discovered d : ext.tab.discoveredSnapshot()) {
            ext.saveDiscovered(d);
        }
        check(ext.store.size() == 2, "discovered sessions can be saved as accounts");
        ext.scanHistory();
        waitUntil(() -> ext.tab.discoveredCount() == 0, "a second scan offers nothing already saved");
        check(ext.store.size() == 2, "…and adds no duplicates");

        // "Send as every account": one Repeater tab per account
        burp.repeater.clear();
        HttpRequest anyRequest = MockBurp.request("https://shop.acme.io/thing", "GET", hdrs("Accept", "*/*"));
        List<java.awt.Component> onAny = ext.provideMenuItems(MockBurp.contextMenuEvent(anyRequest));
        JMenuItem every = itemNamed(onAny, "WhoAmI: Send as every account (2)");
        check(every != null, "send-as-every-account is offered when there is more than one account");
        SwingUtilities.invokeAndWait(every::doClick);
        check(burp.repeater.size() == 2, "it opens one Repeater tab per account: " + burp.repeater.size());

        System.out.println("extension against mocked Burp: ok");
    }

    // ── Phase 3: Burp session-handling integration ────────────────────────────

    private static void sessionHandlingTests() throws Exception {
        MockBurp burp = new MockBurp();
        WhoAmIExtension ext = new WhoAmIExtension();
        ext.initialize(burp.api());
        check(burp.sessionActions.isEmpty(), "with no accounts there are no session-handling actions");

        Identity admin = ext.store.create("Admin", "CYAN", "acme.io", sessionHeaders("sid=ADMINSID9999"), 1);
        ext.store.add(admin);
        check(burp.sessionActions.size() == 1 && burp.sessionActions.get(0).name().equals("WhoAmI: Admin"),
                "saving an account registers a session-handling action named for it");

        HttpRequest bare = MockBurp.request("https://acme.io/api", "GET", hdrs("Accept", "*/*"));
        burp.sessionActions.get(0).performAction(MockBurp.actionData(bare));        // must not throw
        HttpRequest applied = WhoAmIExtension.applyAccount(bare, admin);
        check(applied.hasHeader("Cookie") && applied.headerValue("Cookie").contains("ADMINSID9999"),
                "the action applies the account's session to a request");

        ext.rename(admin.id(), "Administrator");
        check(burp.sessionActions.get(0).name().equals("WhoAmI: Administrator"), "the action name follows a rename, live");

        ext.delete(admin.id());
        check(burp.sessionActions.isEmpty() && !burp.deregistered.isEmpty(), "deleting an account deregisters its action");

        System.out.println("session-handling actions: ok");
    }

    private static void waitUntil(java.util.function.BooleanSupplier cond, String what) throws Exception {
        long end = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < end) {
            SwingUtilities.invokeAndWait(() -> { });
            if (cond.getAsBoolean()) {
                break;
            }
            Thread.sleep(50);
        }
        check(cond.getAsBoolean(), what);
    }

    private static JMenuItem itemNamed(List<java.awt.Component> items, String text) {
        for (java.awt.Component c : items) {
            if (c instanceof JMenuItem && text.equals(((JMenuItem) c).getText())) {
                return (JMenuItem) c;
            }
        }
        return null;
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
