# WhoAmI for Burp Suite

Testing an application as several accounts means keeping several sessions
straight — which cookie is the admin's, which bearer token is the read-only
user's, which request in the proxy history belongs to whom. WhoAmI holds each
account's session under a **name** and a **colour**, recognises it in the
traffic, keeps it current, and lends it to a request on demand.

One jar, no dependencies, Burp Suite Community and Professional.

## What it does

- **Save an account.** Right-click any request → **WhoAmI: Save as new
  account**. Its Cookie, Authorization, CSRF and API-key headers are captured
  under a name you give and a colour picked for you.
- **Find the accounts already in your history.** *Scan HTTP history* groups the
  proxy history by session and lists each account it finds — **one per
  session, so a site you browsed as two users comes back as two accounts**,
  told apart by the cookie or token that differs. Select the ones you want and
  *Save*. A cookie the server rotated mid-session does not split an account in
  two (requests are also linked by JWT subject).
- **See who is who.** Every request in the proxy that carries a saved
  account's session is highlighted in that account's colour and commented with
  its name — so a glance down the history tells you which account made what.
  The colours are Burp's own nine (the only ones a row can take); the tab
  shows them as modern chips.
- **Stay current.** When the server rotates a session cookie (a `Set-Cookie`
  on that account's traffic) the saved account follows it, and a bearer token
  that is re-issued for the same JWT subject is adopted too. No re-saving after
  a token refresh.
- **Send as someone else.** Right-click a request → **WhoAmI: Send as →** an
  account, and it opens in Repeater wearing that account's session, in a named
  tab. *Send as (no session)* strips the session — the quickest check for "what
  does this do unauthenticated" — and *Send as every account* opens one
  Repeater tab per account, the same request as each, for an authorization
  check in one click.
- **Read the token.** For a JWT, the tab shows its subject, its role/scope and
  when it expires (an expired one in red), and a per-account count of the
  requests seen wearing it since the extension loaded.

## The tab

A table of accounts — colour, name, host, and, from the JWT, subject, role and
expiry — with the selected account's session headers shown below. Values are
**masked** by default (they are live credentials); *Reveal values* shows them.
Rename, recolour and delete from the toolbar.

## Where accounts are kept

In the **Burp project file**, where this traffic already lives — so your
accounts are there when you reopen the project, and nowhere else. Turn
*Remember accounts in this project file* off and they live only until the
extension is unloaded. They are **never** written to Burp's global settings,
never sent anywhere, and no saved credential is ever checked against any
service.

## Build

JDK 17 or newer.

```bash
./gradlew jar          # build/libs/whoami-burp.jar
./gradlew harness      # the extension against a mocked Burp API
```

`python tools/build.py --test` does both with nothing but a JDK.

| Class | Role |
|---|---|
| `WhoAmIExtension` | the Montoya glue: proxy handlers, the context menu, persistence |
| `WhoAmITab` | the Swing tab |
| `Store` | the saved accounts and the rule that matches a request to one |
| `Discovery` | grouping the proxy history into one candidate account per session |
| `Identity` | one account: its headers, its colour, its serialization |
| `Credentials` | which headers carry a session, and what identifies an account |
| `Jwt` · `Json` | reading what a JWT claims (never verifying it) |

## How it is verified

`./gradlew harness` loads the real extension class against dynamic proxies of
the Montoya interfaces and drives it: an account loaded from the project file,
a request recognised and coloured, a cookie refreshed from a `Set-Cookie`, a
token adopted on a subject match, *Send as* / *Send as (no session)* / *Send as
every account* through Repeater, two sessions discovered in a history and saved
as accounts, and the project-file persistence turned on and off. It also feeds the
parsers input written to make them hang — a JWT that nests without end, a
megabyte of claims, fifty thousand cookies — and requires that they stay quick
and never throw. CI runs it on Linux and Windows for every push.

## How it recognises an account — and its limits

An account is matched when a value that identifies it appears in a request:
a session cookie (chosen by cookie name), or a bearer / token / API-key header.
The account sharing the most such values wins; the most recently used breaks a
tie. So:

- Colouring starts when the extension is loaded. It reads the live proxy
  stream, not history already captured — use *Scan HTTP history* for traffic
  from before.
- Two accounts that happen to share a value (the same CSRF token, say) can be
  told apart only by the values they do not share.
- A cookie the server rotates is adopted only when something stable confirms
  the session is still the same account — another session cookie or a bearer
  token. Logging out and in as a different user reuses the cookie name with a
  new value, so a single-cookie session that is rotated this way is *not*
  followed (that is how one account avoids swallowing another's login); the
  account simply stops matching. Right-click a fresh request →
  *WhoAmI: Update "…" from this request* to re-point it.
- It reads a JWT; it does not check its signature. Nothing it shows proves a
  token is genuine or unexpired on the server — only what the token asserts.

## License

MIT
