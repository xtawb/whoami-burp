package whoami.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import java.awt.Component;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * A stand-in for Burp, built from dynamic proxies over the real Montoya
 * interfaces: enough of the API to load the extension and push requests and
 * responses through it without a Burp process. Unanswered methods return a
 * harmless default, so the extension's real code paths run as they would
 * against Burp.
 */
final class MockBurp {

    final Map<String, String> projectData = Collections.synchronizedMap(new HashMap<>());
    final Map<String, Boolean> preferences = Collections.synchronizedMap(new HashMap<>());
    final List<String> output = Collections.synchronizedList(new ArrayList<>());
    final List<Object[]> repeater = Collections.synchronizedList(new ArrayList<>());   // {HttpRequest, tabName}
    final List<HttpRequest> history = Collections.synchronizedList(new ArrayList<>());
    final List<burp.api.montoya.http.sessions.SessionHandlingAction> sessionActions = Collections.synchronizedList(new ArrayList<>());
    final List<String> deregistered = Collections.synchronizedList(new ArrayList<>());
    volatile Component suiteTab;

    MockBurp() {
        // the action statics (ProxyRequestReceivedAction.continueWith, …) call this factory;
        // every method returns a harmless mock, which the extension returns and the harness ignores
        ObjectFactoryLocator.FACTORY = mock(MontoyaObjectFactory.class, Map.of());
    }

    @SuppressWarnings("unchecked")
    static <T> T mock(Class<T> type, Map<String, Function<Object[], Object>> answers) {
        InvocationHandler h = (proxy, method, args) -> {
            Function<Object[], Object> f = answers.get(method.getName());
            if (f != null) {
                return f.apply(args == null ? new Object[0] : args);
            }
            switch (method.getName()) {
                case "toString": return "mock(" + type.getSimpleName() + ")";
                case "hashCode": return System.identityHashCode(proxy);
                case "equals": return proxy == args[0];
                default: return defaultFor(method);
            }
        };
        return (T) Proxy.newProxyInstance(MockBurp.class.getClassLoader(), new Class<?>[]{type}, h);
    }

    private static Object defaultFor(Method m) {
        Class<?> r = m.getReturnType();
        if (r == void.class) return null;
        if (r == boolean.class) return false;
        if (r == int.class) return 0;
        if (r == short.class) return (short) 0;
        if (r == long.class) return 0L;
        if (r == byte.class) return (byte) 0;
        if (r == String.class) return "";
        if (r == Optional.class) return Optional.empty();
        if (r == List.class) return new ArrayList<>();
        if (r.isInterface()) return mock(r, Map.of());
        return null;
    }

    // ── message objects ──────────────────────────────────────────────────────

    static HttpHeader header(String name, String value) {
        return mock(HttpHeader.class, Map.of("name", a -> name, "value", a -> value, "toString", a -> name + ": " + value));
    }

    /** An HttpRequest whose header set the with*-methods rebuild, so the extension can transform it. */
    static HttpRequest request(String url, String method, List<String[]> headers) {
        List<HttpHeader> headerObjects = new ArrayList<>();
        for (String[] h : headers) {
            headerObjects.add(header(h[0], h[1]));
        }
        Map<String, Function<Object[], Object>> answers = new HashMap<>();
        answers.put("url", a -> url);
        answers.put("method", a -> method);
        answers.put("headers", a -> headerObjects);
        answers.put("hasHeader", a -> headers.stream().anyMatch(h -> h[0].equalsIgnoreCase((String) a[0])));
        answers.put("headerValue", a -> headers.stream().filter(h -> h[0].equalsIgnoreCase((String) a[0]))
                .map(h -> h[1]).findFirst().orElse(null));
        answers.put("withRemovedHeader", a -> request(url, method, without(headers, (String) a[0])));
        answers.put("withAddedHeader", a -> request(url, method, plus(headers, (String) a[0], (String) a[1])));
        answers.put("withUpdatedHeader", a -> request(url, method, updated(headers, (String) a[0], (String) a[1])));
        answers.put("toString", a -> method + " " + url + " " + headers.size() + " header(s)");
        return mock(HttpRequest.class, answers);
    }

    private static List<String[]> without(List<String[]> headers, String name) {
        List<String[]> out = new ArrayList<>();
        for (String[] h : headers) {
            if (!h[0].equalsIgnoreCase(name)) {
                out.add(h);
            }
        }
        return out;
    }

    private static List<String[]> plus(List<String[]> headers, String name, String value) {
        List<String[]> out = new ArrayList<>(headers);
        out.add(new String[]{name, value});
        return out;
    }

    private static List<String[]> updated(List<String[]> headers, String name, String value) {
        List<String[]> out = new ArrayList<>();
        boolean done = false;
        for (String[] h : headers) {
            if (h[0].equalsIgnoreCase(name) && !done) {
                out.add(new String[]{h[0], value});
                done = true;
            } else {
                out.add(h);
            }
        }
        if (!done) {
            out.add(new String[]{name, value});
        }
        return out;
    }

    /** A mutable Annotations, as an InterceptedRequest hands it to a handler. */
    static Annotations annotations(String notes) {
        String[] note = {notes};
        HighlightColor[] colour = {HighlightColor.NONE};
        return mock(Annotations.class, Map.of(
                "notes", a -> note[0],
                "highlightColor", a -> colour[0],
                "setNotes", a -> { note[0] = (String) a[0]; return null; },
                "setHighlightColor", a -> { colour[0] = (HighlightColor) a[0]; return null; }));
    }

    static InterceptedRequest interceptedRequest(String url, String method, List<String[]> headers, Annotations annotations) {
        HttpRequest base = request(url, method, headers);
        Map<String, Function<Object[], Object>> answers = new HashMap<>();
        answers.put("url", a -> url);
        answers.put("method", a -> method);
        answers.put("headers", a -> base.headers());
        answers.put("annotations", a -> annotations);
        return mock(InterceptedRequest.class, answers);
    }

    static Cookie cookie(String name, String value) {
        return mock(Cookie.class, Map.of("name", a -> name, "value", a -> value));
    }

    static InterceptedResponse interceptedResponse(HttpRequest initiating, List<Cookie> cookies) {
        return mock(InterceptedResponse.class, Map.of(
                "initiatingRequest", a -> initiating,
                "cookies", a -> cookies,
                "statusCode", a -> (short) 200));
    }

    static HttpRequestResponse requestResponse(HttpRequest request) {
        return mock(HttpRequestResponse.class, Map.of(
                "request", a -> request,
                "response", a -> (HttpResponse) null));
    }

    static burp.api.montoya.http.sessions.SessionHandlingActionData actionData(HttpRequest request) {
        return mock(burp.api.montoya.http.sessions.SessionHandlingActionData.class, Map.of(
                "request", a -> request,
                "macroRequestResponses", a -> new ArrayList<>(),
                "annotations", a -> annotations(null)));
    }

    static ContextMenuEvent contextMenuEvent(HttpRequest request) {
        List<HttpRequestResponse> selected = new ArrayList<>();
        selected.add(requestResponse(request));
        return mock(ContextMenuEvent.class, Map.of(
                "selectedRequestResponses", a -> selected,
                "messageEditorRequestResponse", a -> Optional.<MessageEditorHttpRequestResponse>empty()));
    }

    // ── the API object ───────────────────────────────────────────────────────

    MontoyaApi api() {
        Object prefs = mock(burp.api.montoya.persistence.Preferences.class, Map.of(
                "getBoolean", a -> preferences.get((String) a[0]),
                "setBoolean", a -> { preferences.put((String) a[0], (Boolean) a[1]); return null; }));
        Object data = mock(burp.api.montoya.persistence.PersistedObject.class, Map.of(
                "getString", a -> projectData.get((String) a[0]),
                "setString", a -> { projectData.put((String) a[0], (String) a[1]); return null; },
                "deleteString", a -> { projectData.remove((String) a[0]); return null; }));
        Object persistence = mock(burp.api.montoya.persistence.Persistence.class, Map.of(
                "preferences", a -> prefs, "extensionData", a -> data));
        Object ui = mock(burp.api.montoya.ui.UserInterface.class, Map.of(
                "registerSuiteTab", a -> { suiteTab = (Component) a[1]; return mock(burp.api.montoya.core.Registration.class, Map.of()); },
                "registerContextMenuItemsProvider", a -> mock(burp.api.montoya.core.Registration.class, Map.of())));
        Object extension = mock(burp.api.montoya.extension.Extension.class, Map.of(
                "setName", a -> null,
                "registerUnloadingHandler", a -> mock(burp.api.montoya.core.Registration.class, Map.of())));
        Object logging = mock(burp.api.montoya.logging.Logging.class, Map.of(
                "logToOutput", a -> { output.add(String.valueOf(a[0])); return null; },
                "logToError", a -> { output.add("ERROR " + a[0]); return null; }));
        Object proxy = mock(burp.api.montoya.proxy.Proxy.class, Map.of(
                "registerRequestHandler", a -> mock(burp.api.montoya.core.Registration.class, Map.of()),
                "registerResponseHandler", a -> mock(burp.api.montoya.core.Registration.class, Map.of()),
                "history", a -> {
                    List<burp.api.montoya.proxy.ProxyHttpRequestResponse> items = new ArrayList<>();
                    for (HttpRequest request : history) {
                        items.add(mock(burp.api.montoya.proxy.ProxyHttpRequestResponse.class,
                                Map.of("finalRequest", x -> request)));
                    }
                    return items;
                }));
        Object repeaterApi = mock(burp.api.montoya.repeater.Repeater.class, Map.of(
                "sendToRepeater", a -> { repeater.add(new Object[]{a[0], a.length > 1 ? a[1] : ""}); return null; }));
        Object http = mock(burp.api.montoya.http.Http.class, Map.of(
                "registerSessionHandlingAction", a -> {
                    burp.api.montoya.http.sessions.SessionHandlingAction action =
                            (burp.api.montoya.http.sessions.SessionHandlingAction) a[0];
                    sessionActions.add(action);
                    return mock(burp.api.montoya.core.Registration.class, Map.of(
                            "deregister", x -> { deregistered.add(action.name()); sessionActions.remove(action); return null; }));
                }));
        return mock(MontoyaApi.class, Map.of(
                "persistence", a -> persistence, "userInterface", a -> ui, "extension", a -> extension,
                "logging", a -> logging, "proxy", a -> proxy, "repeater", a -> repeaterApi, "http", a -> http));
    }
}
