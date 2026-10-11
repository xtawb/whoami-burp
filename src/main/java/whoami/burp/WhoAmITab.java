package whoami.burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * The "WhoAmI" tab. Two views: the saved <b>Accounts</b> — a modern coloured
 * table with the selected account's session shown below, masked — and
 * <b>Discovered</b>, the accounts found in the proxy history, ready to save.
 * Pure Swing; it reaches the extension through {@link Actions}, so it can be
 * built and driven outside Burp.
 */
final class WhoAmITab extends JPanel {

    private static final long serialVersionUID = 1L;

    interface Actions {
        void rename(String id, String name);

        void recolour(String id, String colour);

        void delete(String id);

        void clearAll();

        void rememberInProjectChanged(boolean remember);

        void scanHistory();

        void saveDiscovered(Discovered discovered);
    }

    /** A session found in the history, ready to become an account. */
    static final class Discovered {
        final String suggestedName;
        final String host;
        final int requests;
        final String subject;
        final String samplePath;
        final LinkedHashMap<String, String> headers;

        Discovered(String suggestedName, String host, int requests, String subject, String samplePath,
                   LinkedHashMap<String, String> headers) {
            this.suggestedName = suggestedName;
            this.host = host;
            this.requests = requests;
            this.subject = subject;
            this.samplePath = samplePath;
            this.headers = headers;
        }
    }

    static final int COL_COLOUR = 0, COL_NAME = 1, COL_HOST = 2, COL_SUBJECT = 3, COL_ROLE = 4,
            COL_EXPIRES = 5, COL_SEEN = 6, COL_HEADERS = 7;
    private static final String[] ACCOUNT_COLUMNS = {"", "Name", "Host", "Subject (JWT)", "Role", "Token expires", "Seen", "Session headers"};
    private static final String[] DISCOVERED_COLUMNS = {"Suggested name", "Host", "Requests", "Subject (JWT)", "Sample path"};
    private static final DateTimeFormatter WHEN = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());

    final JCheckBox rememberInProject = new JCheckBox("Remember accounts in this project file", true);
    final JCheckBox reveal = new JCheckBox("Reveal values", false);

    private final Actions actions;
    private final JTabbedPane tabs = new JTabbedPane();
    private final AccountsModel accountsModel = new AccountsModel();
    private final DiscoveredModel discoveredModel = new DiscoveredModel();
    final JTable table = new JTable(accountsModel);
    final JTable discoveredTable = new JTable(discoveredModel);
    private final JTextArea detail = new JTextArea();
    private final JLabel status = new JLabel(" ");
    private List<Identity> rows = new ArrayList<>();
    private List<Discovered> discovered = new ArrayList<>();

    WhoAmITab(Actions actions) {
        super(new BorderLayout(0, 4));
        this.actions = actions;
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        tabs.addTab("Accounts", accountsPanel());
        tabs.addTab("Discovered", discoveredPanel());
        add(tabs, BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);
        refreshTitles();
        showDetail();

        // the "Seen" counts change on proxy threads; repaint them a few times a second
        Timer live = new Timer(1500, e -> {
            if (!rows.isEmpty()) {
                accountsModel.fireTableRowsUpdated(0, rows.size() - 1);
            }
        });
        live.setRepeats(true);
        live.start();
    }

    // ── the Accounts view ──────────────────────────────────────────────────

    private JPanel accountsPanel() {
        JPanel bar = new JPanel(new WrapLayout());
        rememberInProject.setToolTipText("Keep saved accounts in the Burp project file (where this traffic already is). "
                + "Off: accounts live only until the extension is unloaded. Never written to Burp's global settings.");
        rememberInProject.addActionListener(e -> actions.rememberInProjectChanged(rememberInProject.isSelected()));
        reveal.setToolTipText("Show the full session values below. Off by default: these are live credentials.");
        reveal.addActionListener(e -> showDetail());
        bar.add(rememberInProject);
        bar.add(reveal);
        bar.add(button("Scan HTTP history", e -> actions.scanHistory()));
        bar.add(button("Rename", e -> renameSelected()));
        bar.add(button("Set colour", e -> colourMenu()));
        bar.add(button("Delete", e -> deleteSelected()));
        bar.add(button("Clear all", e -> actions.clearAll()));

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setRowHeight(Math.max(table.getRowHeight(), 22));
        table.setShowGrid(false);
        table.setIntercellSpacing(new java.awt.Dimension(0, 0));
        table.getColumnModel().getColumn(COL_COLOUR).setMaxWidth(30);
        table.getColumnModel().getColumn(COL_COLOUR).setCellRenderer(new SwatchRenderer());
        table.getColumnModel().getColumn(COL_SEEN).setMaxWidth(60);
        AccountCell cell = new AccountCell();
        for (int c = 1; c < ACCOUNT_COLUMNS.length; c++) {
            table.getColumnModel().getColumn(c).setCellRenderer(cell);
        }
        int[] widths = {30, 170, 190, 200, 130, 150, 50, 220};
        for (int i = 0; i < widths.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showDetail();
            }
        });

        detail.setEditable(false);
        detail.setLineWrap(true);
        detail.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), new JScrollPane(detail));
        split.setResizeWeight(0.68);
        split.setBorder(null);
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.add(bar, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    // ── the Discovered view ──────────────────────────────────────────────────

    private JPanel discoveredPanel() {
        JPanel bar = new JPanel(new WrapLayout());
        bar.add(new JLabel("Accounts found in the proxy history — one per session, so several accounts on one site show separately."));
        bar.add(button("Scan HTTP history", e -> actions.scanHistory()));
        bar.add(button("Save selected", e -> saveDiscovered(false)));
        bar.add(button("Save all", e -> saveDiscovered(true)));

        discoveredTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        discoveredTable.setAutoCreateRowSorter(true);
        discoveredTable.setRowHeight(Math.max(discoveredTable.getRowHeight(), 22));
        discoveredTable.setShowGrid(false);
        int[] widths = {200, 190, 70, 220, 260};
        for (int i = 0; i < widths.length && i < discoveredTable.getColumnModel().getColumnCount(); i++) {
            discoveredTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.add(bar, BorderLayout.NORTH);
        panel.add(new JScrollPane(discoveredTable), BorderLayout.CENTER);
        return panel;
    }

    private static JButton button(String text, java.awt.event.ActionListener l) {
        JButton b = new JButton(text);
        b.addActionListener(l);
        return b;
    }

    // ── updates from the extension (any thread) ──────────────────────────────

    void setAccounts(List<Identity> accounts) {
        onEdt(() -> {
            String selectedId = selectedId();
            rows = new ArrayList<>(accounts);
            accountsModel.fireTableDataChanged();
            if (selectedId != null) {
                for (int i = 0; i < rows.size(); i++) {
                    if (rows.get(i).id().equals(selectedId)) {
                        int view = table.convertRowIndexToView(i);
                        table.getSelectionModel().setSelectionInterval(view, view);
                    }
                }
            }
            refreshTitles();
            showDetail();
        });
    }

    void setDiscovered(List<Discovered> found) {
        onEdt(() -> {
            discovered = new ArrayList<>(found);
            discoveredModel.fireTableDataChanged();
            refreshTitles();
            tabs.setSelectedIndex(1);
            setStatus(found.isEmpty() ? "No new accounts found in the history."
                    : found.size() + " account(s) found in the history — select and Save.");
        });
    }

    void setRememberInProject(boolean remember) {
        onEdt(() -> rememberInProject.setSelected(remember));
    }

    void setStatus(String text) {
        onEdt(() -> status.setText(text));
    }

    private void refreshTitles() {
        tabs.setTitleAt(0, "Accounts (" + rows.size() + ")");
        tabs.setTitleAt(1, "Discovered" + (discovered.isEmpty() ? "" : " (" + discovered.size() + ")"));
    }

    // ── behaviour ────────────────────────────────────────────────────────────

    private Identity selected() {
        int view = table.getSelectedRow();
        if (view < 0) {
            return null;
        }
        int modelRow = table.convertRowIndexToModel(view);
        return modelRow >= 0 && modelRow < rows.size() ? rows.get(modelRow) : null;
    }

    private String selectedId() {
        Identity identity = selected();
        return identity == null ? null : identity.id();
    }

    private void renameSelected() {
        Identity identity = selected();
        if (identity == null) {
            return;
        }
        String name = javax.swing.JOptionPane.showInputDialog(this, "Account name:", identity.name());
        if (name != null && !name.trim().isEmpty()) {
            actions.rename(identity.id(), name.trim());
        }
    }

    private void deleteSelected() {
        Identity identity = selected();
        if (identity == null) {
            return;
        }
        int ok = javax.swing.JOptionPane.showConfirmDialog(this, "Delete account \"" + identity.name() + "\"?",
                "WhoAmI", javax.swing.JOptionPane.OK_CANCEL_OPTION);
        if (ok == javax.swing.JOptionPane.OK_OPTION) {
            actions.delete(identity.id());
        }
    }

    private void colourMenu() {
        Identity identity = selected();
        if (identity == null) {
            return;
        }
        JPopupMenu menu = new JPopupMenu();
        for (String colour : Store.PALETTE) {
            JMenuItem item = new JMenuItem(pretty(colour), new PillIcon(rgb(colour), 14, 14));
            item.addActionListener(e -> actions.recolour(identity.id(), colour));
            menu.add(item);
        }
        JMenuItem none = new JMenuItem("None", new PillIcon(null, 14, 14));
        none.addActionListener(e -> actions.recolour(identity.id(), "NONE"));
        menu.add(none);
        JPanel bar = (JPanel) ((JPanel) tabs.getComponentAt(0)).getComponent(0);
        for (Component c : bar.getComponents()) {
            if (c instanceof JButton && "Set colour".equals(((JButton) c).getText())) {
                menu.show(c, 0, c.getHeight());
                return;
            }
        }
    }

    private void saveDiscovered(boolean all) {
        int[] viewRows = all ? allRows(discoveredTable) : discoveredTable.getSelectedRows();
        List<Discovered> chosen = new ArrayList<>();
        for (int view : viewRows) {
            int modelRow = discoveredTable.convertRowIndexToModel(view);
            if (modelRow >= 0 && modelRow < discovered.size()) {
                chosen.add(discovered.get(modelRow));
            }
        }
        if (chosen.isEmpty()) {
            setStatus("Select a discovered account first, or use Save all.");
            return;
        }
        for (Discovered d : chosen) {
            actions.saveDiscovered(d);
        }
        discovered.removeAll(chosen);
        discoveredModel.fireTableDataChanged();
        refreshTitles();
        setStatus("Saved " + chosen.size() + " account(s).");
    }

    private static int[] allRows(JTable t) {
        int[] rows = new int[t.getRowCount()];
        for (int i = 0; i < rows.length; i++) {
            rows[i] = i;
        }
        return rows;
    }

    private void showDetail() {
        Identity identity = selected();
        if (identity == null) {
            detail.setText("Select an account to see its session headers.\n\n"
                    + "Save one with a right-click on any request (WhoAmI → Save as new account), "
                    + "or press \"Scan HTTP history\" to find the accounts already in your traffic.");
            detail.setCaretPosition(0);
            return;
        }
        StringBuilder out = new StringBuilder();
        out.append(identity.name());
        if (!identity.host().isEmpty()) {
            out.append("   @ ").append(identity.host());
        }
        if (identity.seenCount() > 0) {
            out.append("   • seen on ").append(identity.seenCount()).append(" request(s) since load");
        }
        out.append("\n\n");
        for (Map.Entry<String, String> header : identity.headers().entrySet()) {
            out.append(header.getKey()).append(": ").append(shownValue(header.getKey(), header.getValue())).append('\n');
        }
        Jwt jwt = identity.jwt();
        if (jwt != null) {
            out.append('\n').append("JWT");
            if (!jwt.subject().isEmpty()) {
                out.append("  subject=").append(jwt.subject());
            }
            if (!jwt.role().isEmpty()) {
                out.append("  role=").append(jwt.role());
            }
            if (jwt.hasExpiry()) {
                out.append("  expires=").append(WHEN.format(Instant.ofEpochSecond(jwt.expiresAt())));
                if (jwt.isExpired(System.currentTimeMillis() / 1000)) {
                    out.append(" (EXPIRED)");
                }
            }
            out.append('\n');
        }
        detail.setText(out.toString());
        detail.setCaretPosition(0);
    }

    private String shownValue(String name, String value) {
        if (reveal.isSelected()) {
            return value;
        }
        if (name.equalsIgnoreCase("cookie")) {
            StringBuilder out = new StringBuilder();
            for (Map.Entry<String, String> cookie : Credentials.cookies(value).entrySet()) {
                out.append(out.length() > 0 ? "; " : "").append(cookie.getKey()).append('=').append(mask(cookie.getValue()));
            }
            return out.length() > 0 ? out.toString() : mask(value);
        }
        String scheme = "";
        String token = value;
        if (value.indexOf(' ') > 0 && Character.isLetter(value.charAt(0))) {
            int space = value.indexOf(' ');
            scheme = value.substring(0, space + 1);
            token = value.substring(space + 1);
        }
        return scheme + mask(token);
    }

    /** First and last characters, the middle replaced by "…". */
    static String mask(String value) {
        int n = value.length();
        if (n == 0) {
            return "";
        }
        if (n <= 8) {
            return value.substring(0, Math.min(2, n)) + "…";
        }
        if (n <= 20) {
            return value.substring(0, 4) + "…" + value.substring(n - 2);
        }
        return value.substring(0, 8) + "…" + value.substring(n - 4);
    }

    private static void onEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeLater(r);
        }
    }

    private static String pretty(String colour) {
        return colour.charAt(0) + colour.substring(1).toLowerCase(Locale.ROOT);
    }

    // ── colours ────────────────────────────────────────────────────────────

    /** A highlight colour as a solid swatch colour. The nine are Burp's own; only their shade is ours. */
    static Color rgb(String colour) {
        switch (colour) {
            case "RED": return new Color(0xE2544B);
            case "ORANGE": return new Color(0xE8833A);
            case "YELLOW": return new Color(0xE3B341);
            case "GREEN": return new Color(0x4CAF68);
            case "CYAN": return new Color(0x3FB6C4);
            case "BLUE": return new Color(0x4A90D9);
            case "PINK": return new Color(0xE0699A);
            case "MAGENTA": return new Color(0x9B6Fc6);
            case "GRAY": case "GREY": return new Color(0x9AA0A6);
            default: return null;
        }
    }

    /** A soft rounded colour chip, drawn with antialiasing. */
    static final class PillIcon implements javax.swing.Icon {
        private final Color colour;
        private final int w;
        private final int h;

        PillIcon(Color colour, int w, int h) {
            this.colour = colour;
            this.w = w;
            this.h = h;
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int arc = Math.min(w, h);
            if (colour != null) {
                g2.setColor(colour);
                g2.fillRoundRect(x, y, w, h, arc, arc);
            } else {
                g2.setColor(new Color(0x9AA0A6));
                g2.drawRoundRect(x, y, w - 1, h - 1, arc, arc);
            }
            g2.dispose();
        }

        @Override
        public int getIconWidth() {
            return w;
        }

        @Override
        public int getIconHeight() {
            return h;
        }
    }

    private final class SwatchRenderer extends DefaultTableCellRenderer {
        private static final long serialVersionUID = 1L;

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(t, "", sel, focus, r, c);
            int modelRow = t.convertRowIndexToModel(r);
            label.setHorizontalAlignment(SwingConstants.CENTER);
            label.setIcon(modelRow >= 0 && modelRow < rows.size() ? new PillIcon(rgb(rows.get(modelRow).colour()), 14, 14) : null);
            if (!sel) {
                label.setBackground(zebra(t, r));
            }
            return label;
        }
    }

    /** Name in bold, an expired token in red, and quiet zebra striping. */
    private final class AccountCell extends DefaultTableCellRenderer {
        private static final long serialVersionUID = 1L;

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
            Component comp = super.getTableCellRendererComponent(t, v, sel, focus, r, c);
            int column = t.convertColumnIndexToModel(c);
            setFont(getFont().deriveFont(column == COL_NAME ? Font.BOLD : Font.PLAIN));
            if (!sel) {
                comp.setBackground(zebra(t, r));
                boolean expired = column == COL_EXPIRES && String.valueOf(v).contains("expired");
                boolean quiet = column == COL_SEEN && "0".equals(String.valueOf(v));
                comp.setForeground(expired ? new Color(0xE2544B) : quiet ? new Color(0x9AA0A6) : t.getForeground());
            }
            return comp;
        }
    }

    /** A background one step from the table's own, for alternate rows — works on a light or dark theme. */
    private static Color zebra(JTable t, int viewRow) {
        Color bg = t.getBackground();
        if (viewRow % 2 == 0) {
            return bg;
        }
        boolean dark = (bg.getRed() + bg.getGreen() + bg.getBlue()) / 3 < 128;
        int d = dark ? 14 : -10;
        return new Color(clamp(bg.getRed() + d), clamp(bg.getGreen() + d), clamp(bg.getBlue() + d));
    }

    private static int clamp(int v) {
        return Math.max(0, Math.min(255, v));
    }

    // ── table models ──────────────────────────────────────────────────────

    private final class AccountsModel extends AbstractTableModel {
        private static final long serialVersionUID = 1L;

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return ACCOUNT_COLUMNS.length;
        }

        @Override
        public String getColumnName(int c) {
            return ACCOUNT_COLUMNS[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            Identity identity = rows.get(r);
            Jwt jwt = identity.jwt();
            switch (c) {
                case COL_COLOUR: return "";
                case COL_NAME: return identity.name();
                case COL_HOST: return identity.host();
                case COL_SUBJECT: return jwt == null ? "" : jwt.subject();
                case COL_ROLE: return jwt == null ? "" : jwt.role();
                case COL_EXPIRES: return expiry(jwt);
                case COL_SEEN: return Integer.toString(identity.seenCount());
                case COL_HEADERS: return String.join(", ", identity.headers().keySet());
                default: return "";
            }
        }

        private String expiry(Jwt jwt) {
            if (jwt == null || !jwt.hasExpiry()) {
                return "";
            }
            String when = WHEN.format(Instant.ofEpochSecond(jwt.expiresAt()));
            return jwt.isExpired(System.currentTimeMillis() / 1000) ? when + " (expired)" : when;
        }
    }

    private final class DiscoveredModel extends AbstractTableModel {
        private static final long serialVersionUID = 1L;

        @Override
        public int getRowCount() {
            return discovered.size();
        }

        @Override
        public int getColumnCount() {
            return DISCOVERED_COLUMNS.length;
        }

        @Override
        public String getColumnName(int c) {
            return DISCOVERED_COLUMNS[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            Discovered d = discovered.get(r);
            switch (c) {
                case 0: return d.suggestedName;
                case 1: return d.host;
                case 2: return Integer.toString(d.requests);
                case 3: return d.subject;
                case 4: return d.samplePath;
                default: return "";
            }
        }
    }

    JComponent accountsTable() {
        return table;
    }

    // ── for the test harness ──────────────────────────────────────────────────

    int discoveredCount() {
        return discovered.size();
    }

    List<Discovered> discoveredSnapshot() {
        return new ArrayList<>(discovered);
    }
}
