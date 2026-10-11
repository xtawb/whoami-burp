package whoami.burp;

import java.util.ArrayList;
import java.util.List;

/**
 * Reading an authorization check: the same request sent as each account, and
 * as no session, with what each got back. This is the judgement only — the
 * sending is done elsewhere, explicitly, by the extension — so it is a pure
 * function of the responses and can be reasoned about on its own.
 *
 * It does not decide that an application is vulnerable. It points at the thing
 * worth a human's eye: an endpoint that answered two different accounts, or no
 * session at all, with the same thing.
 */
final class AccessCheck {

    /** One account's (or "no session"'s) result. */
    static final class Row {
        final String label;             // the account name, or "(no session)"
        final boolean session;          // false for the no-session row
        final int status;               // HTTP status, or 0 for no response
        final int length;               // response body length in bytes, or -1

        Row(String label, boolean session, int status, int length) {
            this.label = label;
            this.session = session;
            this.status = status;
            this.length = length;
        }

        String access() {
            return AccessCheck.access(status);
        }
    }

    private AccessCheck() {
    }

    /** A status code as a word: what kind of access it is. */
    static String access(int status) {
        if (status == 0) {
            return "no response";
        }
        if (status >= 200 && status < 300) {
            return "allowed";
        }
        if (status == 401 || status == 403) {
            return "denied";
        }
        if (status >= 300 && status < 400) {
            return "redirect";
        }
        if (status >= 500) {
            return "server error";
        }
        return "other (" + status + ")";
    }

    /**
     * One line on what the rows, together, suggest. Flags an endpoint that let more than one
     * account in with near-identical responses, and one that answered without any session — the
     * two shapes of broken access control. It never asserts a finding; it says where to look.
     */
    static String summary(List<Row> rows) {
        List<Row> allowed = new ArrayList<>();
        Row noSession = null;
        for (Row row : rows) {
            if (row.access().equals("allowed")) {
                allowed.add(row);
            }
            if (!row.session) {
                noSession = row;
            }
        }
        List<String> flags = new ArrayList<>();
        if (noSession != null && noSession.access().equals("allowed")) {
            flags.add("the endpoint answered with no session at all — check that it requires authentication");
        }
        List<Row> allowedWithSession = new ArrayList<>();
        for (Row row : allowed) {
            if (row.session) {
                allowedWithSession.add(row);
            }
        }
        if (allowedWithSession.size() >= 2 && nearIdentical(allowedWithSession)) {
            flags.add(allowedWithSession.size() + " accounts got near-identical responses — check whether the endpoint "
                    + "authorizes per account (possible broken access control)");
        }
        if (flags.isEmpty()) {
            return allowed.isEmpty() ? "No account was allowed in." : "Each account's access looks distinct.";
        }
        return "⚠ " + String.join("; ", flags) + ".";
    }

    /** Are these responses close enough in size to be "the same page"? */
    private static boolean nearIdentical(List<Row> rows) {
        int min = Integer.MAX_VALUE;
        int max = Integer.MIN_VALUE;
        for (Row row : rows) {
            min = Math.min(min, row.length);
            max = Math.max(max, row.length);
        }
        if (min < 0) {
            return false;
        }
        return max - min <= 32 || (max > 0 && (max - min) * 100L / max <= 10);     // within 32 bytes, or 10%
    }
}
