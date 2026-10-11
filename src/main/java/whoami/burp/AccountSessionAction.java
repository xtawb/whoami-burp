package whoami.burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;

/**
 * One account, offered to Burp as a session-handling action. Add a session
 * handling rule in Project options → Sessions whose action is "Invoke a Burp
 * extension → WhoAmI: &lt;account&gt;", and Repeater, Intruder and Scanner send
 * their requests with that account's session — kept current by the rest of the
 * extension, so a rotated cookie is applied without touching the rule.
 *
 * The account is held by id, so its name and session are always read live; a
 * deleted account's action does nothing.
 */
final class AccountSessionAction implements SessionHandlingAction {

    private final Store store;
    private final String accountId;

    AccountSessionAction(Store store, String accountId) {
        this.store = store;
        this.accountId = accountId;
    }

    @Override
    public String name() {
        Identity account = store.get(accountId);
        return "WhoAmI: " + (account == null ? "(deleted account)" : account.name());
    }

    @Override
    public ActionResult performAction(SessionHandlingActionData actionData) {
        HttpRequest request = actionData.request();
        Identity account = store.get(accountId);
        if (request == null || account == null) {
            return ActionResult.actionResult(request, actionData.annotations());
        }
        return ActionResult.actionResult(WhoAmIExtension.applyAccount(request, account), actionData.annotations());
    }
}
