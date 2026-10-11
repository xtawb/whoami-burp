package whoami.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import java.awt.Component;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

/**
 * WhoAmI for Burp Suite.
 *
 * Save the cookies and tokens of an account under a name and a colour; from
 * then on, every request that carries that account's session is coloured and
 * labelled in the proxy, its cookies are kept current as the server rotates
 * them, and "Send as" opens a request in Repeater wearing another account's
 * session.
 *
 * Nothing is sent without an explicit action, no credential is checked against
 * any service, and saved accounts live in the Burp project file (or only in
 * memory), never in Burp's global settings.
 */
public final class WhoAmIExtension implements BurpExtension, ProxyRequestHandler, ProxyResponseHandler,
        ContextMenuItemsProvider, WhoAmITab.Actions, Store.Listener {

    static final String VERSION = "0.2.0";
    private static final String ACCOUNTS_KEY = "whoami.accounts.v1";
    private static final String REMEMBER_KEY = "whoami.rememberInProject";

    private MontoyaApi api;
    private Preferences prefs;
    private PersistedObject projectData;
    WhoAmITab tab;                       // package-private: the harness inspects these
    final Store store = new Store();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.prefs = api.persistence().preferences();
        this.projectData = api.persistence().extensionData();
        api.extension().setName("WhoAmI");

        tab = new WhoAmITab(this);
        boolean remember = rememberPreference();
        tab.setRememberInProject(remember);
        if (remember) {
            store.load(projectData.getString(ACCOUNTS_KEY));
        }
        store.setListener(this);

        api.userInterface().registerSuiteTab("WhoAmI", tab);
        api.userInterface().registerContextMenuItemsProvider(this);
        api.proxy().registerRequestHandler(this);
        api.proxy().registerResponseHandler(this);
        api.extension().registerUnloadingHandler(() -> { });

        tab.setAccounts(store.all());
        api.logging().logToOutput("WhoAmI " + VERSION + " loaded with " + store.size() + " account(s).");
    }

    private boolean rememberPreference() {
        try {
            Boolean saved = prefs.getBoolean(REMEMBER_KEY);
            return saved == null || saved;
        } catch (RuntimeException e) {
            return true;
        }
    }

    // ── recognising accounts in proxy traffic ─────────────────────────────────

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        try {
            Identity identity;
            synchronized (store) {
                identity = store.match(sessionHeadersOf(request));
                if (identity != null && identity.refreshTokens(sessionHeadersOf(request), now())) {
                    store.changed();        // a rotated bearer token, confirmed by its subject
                }
            }
            if (identity != null) {
                identity.noteSeen(now());
                // mutate the request's own annotations: a comment the user already wrote is kept
                Annotations annotations = request.annotations();
                if (annotations.notes() == null || annotations.notes().isBlank()) {
                    annotations.setNotes(identity.name());
                }
                annotations.setHighlightColor(highlight(identity.colour()));
            }
        } catch (RuntimeException e) {
            api.logging().logToError("WhoAmI: " + e);
        }
        return ProxyRequestReceivedAction.continueWith(request);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        return ProxyRequestToBeSentAction.continueWith(request);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        try {
            HttpRequest request = response.initiatingRequest();
            if (request != null) {
                LinkedHashMap<String, String> fresh = new LinkedHashMap<>();
                for (Cookie cookie : response.cookies()) {
                    if (cookie.value() != null && !cookie.value().isEmpty()) {
                        fresh.put(cookie.name(), cookie.value());
                    }
                }
                if (!fresh.isEmpty()) {
                    synchronized (store) {
                        Identity identity = store.match(sessionHeadersOf(request));
                        if (identity != null && identity.updateCookies(fresh, now())) {
                            store.changed();
                            tab.setStatus("Refreshed \"" + identity.name() + "\" cookies from the server.");
                        }
                    }
                }
            }
        } catch (RuntimeException e) {
            api.logging().logToError("WhoAmI: " + e);
        }
        return ProxyResponseReceivedAction.continueWith(response);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        return ProxyResponseToBeSentAction.continueWith(response);
    }

    private static HighlightColor highlight(String colour) {
        try {
            return HighlightColor.valueOf(colour);
        } catch (IllegalArgumentException | NullPointerException e) {
            return HighlightColor.NONE;
        }
    }

    // ── the context menu ──────────────────────────────────────────────────────

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        HttpRequest request = requestFrom(event);
        List<Component> items = new ArrayList<>();
        if (request == null) {
            return items;
        }
        LinkedHashMap<String, String> session = sessionHeadersOf(request);
        if (!session.isEmpty()) {
            JMenuItem save = new JMenuItem("WhoAmI: Save as new account");
            save.addActionListener(e -> saveAccount(request, session));
            items.add(save);
            Identity match = store.match(session);
            if (match != null) {
                JMenuItem update = new JMenuItem("WhoAmI: Update \"" + match.name() + "\" from this request");
                update.addActionListener(e -> updateAccount(match.id(), session));
                items.add(update);
            }
        }
        if (store.size() > 0) {
            JMenu sendAs = new JMenu("WhoAmI: Send as");
            for (Identity identity : store.all()) {
                JMenuItem item = new JMenuItem(identity.name());
                item.addActionListener(e -> sendAs(request, identity));
                sendAs.add(item);
            }
            JMenuItem none = new JMenuItem("(no session)");
            none.addActionListener(e -> sendAs(request, null));
            sendAs.add(none);
            items.add(sendAs);

            if (store.size() > 1) {
                // one Repeater tab per account: the same request, each account's session — an authorization check
                JMenuItem every = new JMenuItem("WhoAmI: Send as every account (" + store.size() + ")");
                every.addActionListener(e -> {
                    for (Identity identity : store.all()) {
                        sendAs(request, identity);
                    }
                });
                items.add(every);
            }
        }
        return items;
    }

    private HttpRequest requestFrom(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            HttpRequest request = event.messageEditorRequestResponse().get().requestResponse().request();
            if (request != null) {
                return request;
            }
        }
        for (HttpRequestResponse pair : event.selectedRequestResponses()) {
            if (pair.request() != null) {
                return pair.request();
            }
        }
        return null;
    }

    private void saveAccount(HttpRequest request, LinkedHashMap<String, String> session) {
        String suggested = suggestedName(session, request);
        String name = JOptionPane.showInputDialog(tab, "Name this account:", suggested);
        if (name == null || name.trim().isEmpty()) {
            return;
        }
        Identity identity = store.create(name.trim(), store.nextColour(), hostOf(request.url()), session, now());
        store.add(identity);
        tab.setStatus("Saved account \"" + identity.name() + "\".");
    }

    private void updateAccount(String id, LinkedHashMap<String, String> session) {
        synchronized (store) {
            Identity identity = store.get(id);
            if (identity != null) {
                identity.replaceHeaders(session, now());
                store.changed();
            }
        }
        tab.setStatus("Updated account from this request.");
    }

    private String suggestedName(LinkedHashMap<String, String> session, HttpRequest request) {
        Jwt jwt = Credentials.jwtIn(session);
        if (jwt != null && !jwt.subject().isEmpty()) {
            return jwt.subject();
        }
        String host = hostOf(request.url());
        return host.isEmpty() ? "account " + (store.size() + 1) : host;
    }

    private void sendAs(HttpRequest request, Identity identity) {
        try {
            HttpRequest out = stripSession(request);
            String label;
            if (identity == null) {
                label = "WhoAmI: no session";
            } else {
                for (String[] header : identity.headerPairs()) {
                    out = out.hasHeader(header[0]) ? out.withUpdatedHeader(header[0], header[1])
                            : out.withAddedHeader(header[0], header[1]);
                }
                label = "WhoAmI: " + identity.name();
            }
            api.repeater().sendToRepeater(out, label);
            tab.setStatus("Sent to Repeater (" + label + ").");
        } catch (RuntimeException e) {
            api.logging().logToError("WhoAmI: could not send to Repeater: " + e);
        }
    }

    static HttpRequest stripSession(HttpRequest request) {
        HttpRequest out = request;
        for (HttpHeader header : request.headers()) {
            if (Credentials.carriesSession(header.name())) {
                out = out.withRemovedHeader(header.name());
            }
        }
        return out;
    }

    // ── actions from the tab ──────────────────────────────────────────────────

    @Override
    public void rename(String id, String name) {
        synchronized (store) {
            Identity identity = store.get(id);
            if (identity != null) {
                identity.setName(name);
                store.changed();
            }
        }
    }

    @Override
    public void recolour(String id, String colour) {
        synchronized (store) {
            Identity identity = store.get(id);
            if (identity != null) {
                identity.setColour(colour);
                store.changed();
            }
        }
    }

    @Override
    public void delete(String id) {
        store.remove(id);
    }

    @Override
    public void clearAll() {
        store.clear();
    }

    // ── finding accounts already in the history ───────────────────────────────

    @Override
    public void scanHistory() {
        Thread worker = new Thread(this::doScanHistory, "whoami-scan");
        worker.setDaemon(true);
        worker.start();
    }

    private void doScanHistory() {
        try {
            List<Discovery.Request> requests = new ArrayList<>();
            int total = 0;
            for (ProxyHttpRequestResponse item : api.proxy().history()) {
                HttpRequest request = item.finalRequest();
                if (request == null) {
                    continue;
                }
                total++;
                LinkedHashMap<String, String> session = sessionHeadersOf(request);
                if (!session.isEmpty()) {
                    requests.add(new Discovery.Request(hostOf(request.url()), pathOf(request.url()), session));
                }
            }
            List<Discovery.Candidate> candidates = Discovery.cluster(requests);
            List<WhoAmITab.Discovered> toShow = new ArrayList<>();
            int known = 0;
            synchronized (store) {
                Map<String, Integer> perHost = new HashMap<>();
                for (Identity identity : store.all()) {
                    perHost.merge(identity.host(), 1, Integer::sum);
                }
                for (Discovery.Candidate candidate : candidates) {
                    if (store.match(candidate.headers) != null) {
                        known++;                            // already saved: nothing to offer
                        continue;
                    }
                    String name = candidate.subject.isEmpty()
                            ? (candidate.host.isEmpty() ? "account" : candidate.host) + " #" + perHost.merge(candidate.host, 1, Integer::sum)
                            : candidate.subject;
                    toShow.add(new WhoAmITab.Discovered(name, candidate.host, candidate.requests,
                            candidate.subject, candidate.samplePath, candidate.headers));
                }
            }
            tab.setDiscovered(toShow);
            api.logging().logToOutput("WhoAmI: scanned " + total + " request(s); " + toShow.size()
                    + " new account(s), " + known + " already saved.");
        } catch (RuntimeException e) {
            api.logging().logToError("WhoAmI: history scan failed: " + e);
            tab.setStatus("History scan failed: " + e.getClass().getSimpleName());
        }
    }

    @Override
    public void saveDiscovered(WhoAmITab.Discovered discovered) {
        Identity identity = store.create(discovered.suggestedName, store.nextColour(), discovered.host,
                discovered.headers, now());
        store.add(identity);
    }

    private static String pathOf(String url) {
        try {
            String path = URI.create(url).getPath();
            return path == null || path.isEmpty() ? "/" : path;
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    @Override
    public void rememberInProjectChanged(boolean remember) {
        try {
            prefs.setBoolean(REMEMBER_KEY, remember);
            if (remember) {
                persist();
            } else {
                projectData.deleteString(ACCOUNTS_KEY);         // off: nothing of ours stays on disk
            }
        } catch (RuntimeException e) {
            api.logging().logToError("WhoAmI: " + e);
        }
    }

    // ── the store changed: refresh the tab, and persist when asked to ─────────

    @Override
    public void storeChanged() {
        if (tab != null) {
            tab.setAccounts(store.all());
        }
        if (tab != null && tab.rememberInProject.isSelected()) {
            persist();
        }
    }

    private void persist() {
        try {
            projectData.setString(ACCOUNTS_KEY, store.serialize());
        } catch (RuntimeException e) {
            api.logging().logToError("WhoAmI: could not save accounts: " + e);
        }
    }

    // ── helpers ────────────────────────────────────────────────────────────

    static LinkedHashMap<String, String> sessionHeadersOf(HttpRequest request) {
        List<String[]> pairs = new ArrayList<>();
        for (HttpHeader header : request.headers()) {
            pairs.add(new String[]{header.name(), header.value()});
        }
        return Credentials.sessionHeaders(pairs);
    }

    static String hostOf(String url) {
        try {
            String host = URI.create(url).getHost();
            return host == null ? "" : host.toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    private static long now() {
        return System.currentTimeMillis();
    }
}
