package whoami.burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * The saved accounts, and the one rule that ties the tool together: given a
 * request, which account is it. An account is matched when a value that
 * identifies it — a session cookie, a bearer token — appears in the request;
 * the account sharing the most such values wins, the most recently used
 * breaking a tie.
 *
 * Every account is held here, guarded by one lock, because the proxy threads
 * read it while the UI thread changes it. A change tells the listener, which
 * saves the set and refreshes the table.
 */
final class Store {

    /** Burp's highlight colours, in the order new accounts are coloured. RED is kept for last. */
    static final String[] PALETTE = {"CYAN", "GREEN", "ORANGE", "PINK", "BLUE", "YELLOW", "MAGENTA", "GRAY", "RED"};

    interface Listener {
        void storeChanged();
    }

    private final List<Identity> identities = new ArrayList<>();
    private final Map<String, Identity> byId = new HashMap<>();
    private Listener listener = () -> { };

    void setListener(Listener listener) {
        this.listener = listener == null ? () -> { } : listener;
    }

    static String newId() {
        return UUID.randomUUID().toString();
    }

    synchronized List<Identity> all() {
        return new ArrayList<>(identities);
    }

    synchronized Identity get(String id) {
        return byId.get(id);
    }

    synchronized int size() {
        return identities.size();
    }

    synchronized void add(Identity identity) {
        if (byId.put(identity.id(), identity) == null) {
            identities.add(identity);
        }
        listener.storeChanged();
    }

    synchronized void remove(String id) {
        Identity gone = byId.remove(id);
        if (gone != null) {
            identities.remove(gone);
            listener.storeChanged();
        }
    }

    synchronized void clear() {
        identities.clear();
        byId.clear();
        listener.storeChanged();
    }

    /** Record that an account changed (renamed, recoloured, a cookie refreshed): save and refresh. */
    synchronized void changed() {
        listener.storeChanged();
    }

    /** An unused palette colour, or the least-used one when every colour is taken. */
    synchronized String nextColour() {
        Map<String, Integer> used = new HashMap<>();
        for (Identity identity : identities) {
            used.merge(identity.colour(), 1, Integer::sum);
        }
        String best = PALETTE[0];
        int fewest = Integer.MAX_VALUE;
        for (String colour : PALETTE) {
            int count = used.getOrDefault(colour, 0);
            if (count < fewest) {
                fewest = count;
                best = colour;
                if (count == 0) {
                    break;
                }
            }
        }
        return best;
    }

    synchronized Identity match(Map<String, String> requestSessionHeaders) {
        return match(requestSessionHeaders, "");
    }

    /**
     * The account a request belongs to, or null. The account is the one sharing the most
     * identifying values with the request; a value it used before a rotation still counts, but
     * less than a current one, so fresh traffic always wins over old. The request's host (when
     * known) breaks a tie in favour of the account seen on that host. The most recently used
     * account breaks any remaining tie.
     */
    synchronized Identity match(Map<String, String> requestSessionHeaders, String host) {
        Set<String> values = Credentials.identifyingValues(requestSessionHeaders);
        if (values.isEmpty()) {
            return null;
        }
        String registrable = Credentials.registrable(host);
        Identity best = null;
        int bestScore = 0;
        for (Identity identity : identities) {
            int score = 0;
            for (String value : identity.identifyingValues()) {
                if (values.contains(value)) {
                    score += 10;                        // a current value: the strong signal
                }
            }
            if (score == 0) {
                for (String value : identity.pastValues()) {
                    if (values.contains(value)) {
                        score += 2;                     // a value rotated away from: weaker, but attributes old traffic
                    }
                }
            }
            if (score > 0 && !registrable.isEmpty() && registrable.equals(Credentials.registrable(identity.host()))) {
                score += 1;                             // same site: a tie-breaker, never a match on its own
            }
            if (score > bestScore || (score == bestScore && best != null && score > 0
                    && identity.updatedAt() > best.updatedAt())) {
                best = identity;
                bestScore = score;
            }
        }
        return bestScore > 0 ? best : null;
    }

    // ── persistence (one string, written to the Burp project file) ──────────────

    synchronized String serialize() {
        StringBuilder out = new StringBuilder();
        for (Identity identity : identities) {
            out.append(out.length() > 0 ? "\n" : "").append(identity.serialize());
        }
        return out.toString();
    }

    /** Replace the accounts with those in `blob`. Does not notify: it is the initial load. */
    synchronized void load(String blob) {
        identities.clear();
        byId.clear();
        if (blob == null || blob.isEmpty()) {
            return;
        }
        for (String line : blob.split("\n")) {
            if (line.isEmpty()) {
                continue;
            }
            Identity identity = Identity.parse(line);
            if (identity != null && byId.put(identity.id(), identity) == null) {
                identities.add(identity);
            }
        }
    }

    /** Build a fresh account from a request's session headers. The caller adds it to the store. */
    Identity create(String name, String colour, String host, LinkedHashMap<String, String> sessionHeaders, long now) {
        return new Identity(newId(), name, colour, "", host, now, now, sessionHeaders);
    }
}
