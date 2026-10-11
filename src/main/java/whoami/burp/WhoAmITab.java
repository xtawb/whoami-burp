package whoami.burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * The "WhoAmI" tab. A table of saved accounts — colour, name, host, and what
 * the JWT says — with the selected account's session headers shown below,
 * values masked unless asked for. Pure Swing: it knows nothing about Burp and
 * reaches the extension through {@link Actions}, so it can be built and driven
 * outside Burp.
 */
final class WhoAmITab extends JPanel {

    private static final long serialVersionUID = 1L;

    /** What the tab can ask the extension to do. */
    interface Actions {
        void rename(String id, String name);

        void recolour(String id, String colour);

        void delete(String id);

        void clearAll();

        void rememberInProjectChanged(boolean remember);
    }

    static final int COL_COLOUR = 0, COL_NAME = 1, COL_HOST = 2, COL_SUBJECT = 3, COL_ROLE = 4, COL_EXPIRES = 5, COL_HEADERS = 6;
    private static final String[] COLUMNS = {"", "Name", "Host", "Subject (JWT)", "Role", "Token expires", "Session headers"};
    private static final DateTimeFormatter WHEN = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());

    final JCheckBox rememberInProject = new JCheckBox("Remember accounts in this project file", true);
    final JCheckBox reveal = new JCheckBox("Reveal values", false);

    private final Actions actions;
    private final AccountsModel model = new AccountsModel();
    private final JTable table = new JTable(model);
    private final JTextArea detail = new JTextArea();
    private final JLabel status = new JLabel(" ");
    private List<Identity> rows = new ArrayList<>();

    WhoAmITab(Actions actions) {
        super(new BorderLayout(0, 4));
        this.actions = actions;
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        add(toolbar(), BorderLayout.NORTH);

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setRowHeight(Math.max(table.getRowHeight(), 20));
        table.getColumnModel().getColumn(COL_COLOUR).setMaxWidth(28);
        table.getColumnModel().getColumn(COL_COLOUR).setCellRenderer(new SwatchRenderer());
        int[] widths = {28, 160, 200, 200, 140, 150, 220};
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
        detail.setWrapStyleWord(false);
        detail.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), new JScrollPane(detail));
        split.setResizeWeight(0.7);
        split.setBorder(null);
        add(split, BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);
        showDetail();
    }

    private JPanel toolbar() {
        JPanel bar = new JPanel(new WrapLayout());
        rememberInProject.setToolTipText("Keep saved accounts in the Burp project file (where this traffic already is). "
                + "Off: accounts live only until the extension is unloaded. Never written to Burp's global settings.");
        rememberInProject.addActionListener(e -> actions.rememberInProjectChanged(rememberInProject.isSelected()));
        reveal.setToolTipText("Show the full session values below. Off by default: these are live credentials.");
        reveal.addActionListener(e -> showDetail());
        bar.add(rememberInProject);
        bar.add(reveal);
        bar.add(Box.createHorizontalStrut(10));
        bar.add(button("Rename", e -> renameSelected()));
        bar.add(button("Set colour", e -> colourMenu()));
        bar.add(button("Delete", e -> deleteSelected()));
        bar.add(button("Clear all", e -> actions.clearAll()));
        return bar;
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
            model.fireTableDataChanged();
            if (selectedId != null) {
                for (int i = 0; i < rows.size(); i++) {
                    if (rows.get(i).id().equals(selectedId)) {
                        int view = table.convertRowIndexToView(i);
                        table.getSelectionModel().setSelectionInterval(view, view);
                    }
                }
            }
            status.setText(accounts.size() + " account(s)");
            showDetail();
        });
    }

    void setRememberInProject(boolean remember) {
        onEdt(() -> rememberInProject.setSelected(remember));
    }

    void setStatus(String text) {
        onEdt(() -> status.setText(text));
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
            JMenuItem item = new JMenuItem(colour.charAt(0) + colour.substring(1).toLowerCase(Locale.ROOT), swatch(colour, 12));
            item.addActionListener(e -> actions.recolour(identity.id(), colour));
            menu.add(item);
        }
        JMenuItem none = new JMenuItem("None");
        none.addActionListener(e -> actions.recolour(identity.id(), "NONE"));
        menu.add(none);
        for (Component c : getToolbarButtons()) {
            if (c instanceof JButton && "Set colour".equals(((JButton) c).getText())) {
                menu.show(c, 0, c.getHeight());
                return;
            }
        }
    }

    private Component[] getToolbarButtons() {
        return ((JPanel) getComponent(0)).getComponents();
    }

    private void showDetail() {
        Identity identity = selected();
        if (identity == null) {
            detail.setText("Select an account to see its session headers.\n\n"
                    + "Save one with a right-click on any request: WhoAmI → Save as new account.");
            detail.setCaretPosition(0);
            return;
        }
        StringBuilder out = new StringBuilder();
        out.append(identity.name());
        if (!identity.host().isEmpty()) {
            out.append("   @ ").append(identity.host());
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

    /** A header value as shown: masked unless "Reveal values" is on; a Cookie masked cookie by cookie. */
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
        if (value.length() > 0 && value.indexOf(' ') > 0 && Character.isLetter(value.charAt(0))) {
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

    // ── colours ────────────────────────────────────────────────────────────

    /** A highlight colour as a solid swatch colour for the table and menus. */
    static Color rgb(String colour) {
        switch (colour) {
            case "RED": return new Color(0xE53935);
            case "ORANGE": return new Color(0xFB8C00);
            case "YELLOW": return new Color(0xF9A825);
            case "GREEN": return new Color(0x43A047);
            case "CYAN": return new Color(0x00ACC1);
            case "BLUE": return new Color(0x1E88E5);
            case "PINK": return new Color(0xEC407A);
            case "MAGENTA": return new Color(0x8E24AA);
            case "GRAY": case "GREY": return new Color(0x9E9E9E);
            default: return null;
        }
    }

    private static ImageIcon swatch(String colour, int size) {
        java.awt.image.BufferedImage image = new java.awt.image.BufferedImage(size, size, java.awt.image.BufferedImage.TYPE_INT_ARGB);
        java.awt.Graphics2D g = image.createGraphics();
        Color c = rgb(colour);
        if (c != null) {
            g.setColor(c);
            g.fillRect(0, 0, size, size);
        }
        g.setColor(Color.GRAY);
        g.drawRect(0, 0, size - 1, size - 1);
        g.dispose();
        return new ImageIcon(image);
    }

    private final class SwatchRenderer extends DefaultTableCellRenderer {
        private static final long serialVersionUID = 1L;

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
            Component comp = super.getTableCellRendererComponent(t, "", sel, focus, r, c);
            int modelRow = t.convertRowIndexToModel(r);
            if (modelRow >= 0 && modelRow < rows.size()) {
                setIcon(swatch(rows.get(modelRow).colour(), 12));
            }
            setText("");
            return comp;
        }
    }

    // ── table model ────────────────────────────────────────────────────────

    private final class AccountsModel extends AbstractTableModel {
        private static final long serialVersionUID = 1L;

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int c) {
            return COLUMNS[c];
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

    Dimension tablePreferredSize() {
        return table.getPreferredSize();
    }
}
