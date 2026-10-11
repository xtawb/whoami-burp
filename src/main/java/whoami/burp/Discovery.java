package whoami.burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Finding the accounts already in the proxy history. Each request carries the
 * session it was made with; this groups the requests that belong to the same
 * session into one candidate account — so a site browsed as an admin and as a
 * user comes back as two candidates, not one.
 *
 * Requests are linked when they share a value that identifies a session (a
 * session cookie, a bearer token) or the same JWT subject — so a cookie the
 * server rotated mid-session does not split one account into two. A request
 * carrying no session is ignored. Everything here is a pure function of the
 * requests it is given.
 */
final class Discovery {

    /** One request from the history: where it went, and the session it carried. */
    static final class Request {
        final String host;
        final String path;
        final LinkedHashMap<String, String> session;

        Request(String host, String path, LinkedHashMap<String, String> session) {
            this.host = host == null ? "" : host;
            this.path = path == null ? "" : path;
            this.session = session;
        }
    }

    /** One session found across the history: the account it looks like, and how to save it. */
    static final class Candidate {
        final String host;                  // where it was seen most
        final List<String> hosts;           // every host it was seen on
        final int requests;
        final String samplePath;
        final String subject;               // JWT subject, or ""
        final String role;                  // JWT role/scope, or ""
        final LinkedHashMap<String, String> headers;    // the richest session seen, ready to save

        Candidate(String host, List<String> hosts, int requests, String samplePath, String subject, String role,
                  LinkedHashMap<String, String> headers) {
            this.host = host;
            this.hosts = hosts;
            this.requests = requests;
            this.samplePath = samplePath;
            this.subject = subject;
            this.role = role;
            this.headers = headers;
        }
    }

    private static final String SUBJECT = "\u0000sub:";     // a linking key that cannot be a real token value

    private Discovery() {
    }

    static List<Candidate> cluster(List<Request> requests) {
        Map<String, String> parent = new HashMap<>();
        List<Set<String>> keys = new ArrayList<>();
        for (Request request : requests) {
            Set<String> k = new LinkedHashSet<>(Credentials.identifyingValues(request.session));
            Jwt jwt = Credentials.jwtIn(request.session);
            if (jwt != null && !jwt.subject().isEmpty()) {
                k.add(SUBJECT + jwt.subject());
            }
            keys.add(k);
            for (String key : k) {
                parent.putIfAbsent(key, key);
            }
        }
        for (Set<String> k : keys) {
            String first = null;
            for (String key : k) {
                if (first == null) {
                    first = key;
                } else {
                    union(parent, first, key);
                }
            }
        }
        Map<String, List<Integer>> groups = new LinkedHashMap<>();
        for (int i = 0; i < requests.size(); i++) {
            if (keys.get(i).isEmpty()) {
                continue;                                   // an anonymous request belongs to no account
            }
            String root = find(parent, keys.get(i).iterator().next());
            groups.computeIfAbsent(root, x -> new ArrayList<>()).add(i);
        }

        List<Candidate> out = new ArrayList<>();
        for (List<Integer> indices : groups.values()) {
            int rep = indices.get(0);
            for (int i : indices) {
                if (requests.get(i).session.size() > requests.get(rep).session.size()) {
                    rep = i;                                // the richest session is the one worth saving
                }
            }
            Map<String, Integer> hostCount = new LinkedHashMap<>();
            for (int i : indices) {
                hostCount.merge(requests.get(i).host, 1, Integer::sum);
            }
            Request representative = requests.get(rep);
            Jwt jwt = Credentials.jwtIn(representative.session);
            out.add(new Candidate(mostCommon(hostCount), new ArrayList<>(hostCount.keySet()), indices.size(),
                    representative.path, jwt == null ? "" : jwt.subject(), jwt == null ? "" : jwt.role(),
                    representative.session));
        }
        out.sort((a, b) -> Integer.compare(b.requests, a.requests));
        return out;
    }

    private static String mostCommon(Map<String, Integer> counts) {
        String best = "";
        int most = -1;
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            if (e.getValue() > most) {
                most = e.getValue();
                best = e.getKey();
            }
        }
        return best;
    }

    private static String find(Map<String, String> parent, String x) {
        String root = x;
        while (!root.equals(parent.get(root))) {
            root = parent.get(root);
        }
        while (!x.equals(root)) {                           // path compression
            String next = parent.get(x);
            parent.put(x, root);
            x = next;
        }
        return root;
    }

    private static void union(Map<String, String> parent, String a, String b) {
        parent.put(find(parent, a), find(parent, b));
    }
}
