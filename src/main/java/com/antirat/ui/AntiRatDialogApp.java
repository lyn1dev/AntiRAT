package com.antirat.ui;

import com.antirat.core.Config;

import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Image;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Standalone, isolated desktop UI application for AntiRAT.
 *
 * Runs in its own separate OS process so that it stays open and visible
 * even if Minecraft crashes, halts, or encounters conflicts with other crash handlers.
 *
 * Supports fine-grained, file-by-file whitelisting and deletion.
 */
public final class AntiRatDialogApp {

    public static void main(String[] args) {
        if (args.length < 1) {
            return;
        }

        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Throwable ignored) {}

        String mode = args[0];

        if ("token_access".equalsIgnoreCase(mode) && args.length >= 5) {
            String modId = args[1];
            String fileName = args[2];
            String originPathStr = args[3];
            String configDirStr = args[4];
            String accessPoint = args.length >= 6 ? args[5] : "User#getAccessToken";

            showTokenAccessWindow(modId, fileName, originPathStr, configDirStr, accessPoint);
        } else if ("prelaunch_threat_b64".equalsIgnoreCase(mode) && args.length >= 3) {
            try {
                byte[] decoded = java.util.Base64.getDecoder().decode(args[1]);
                String payload = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
                String configDirStr = args[2];
                showPreLaunchThreatWindow(payload, configDirStr);
            } catch (Exception e) {
                showPreLaunchThreatWindow(args[1], args[2]);
            }
        } else if ("prelaunch_threat".equalsIgnoreCase(mode) && args.length >= 3) {
            String payload = args[1];
            String configDirStr = args[2];

            showPreLaunchThreatWindow(payload, configDirStr);
        }
    }

    private static Image loadModIcon() {
        try (InputStream is = AntiRatDialogApp.class.getResourceAsStream("/assets/antirat/icon.png")) {
            if (is != null) {
                return ImageIO.read(is);
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private static void showTokenAccessWindow(String modId, String fileName, String originPathStr,
                                              String configDirStr, String accessPoint) {
        JFrame frame = new JFrame("AntiRAT - Security Alert (" + modId + ")");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setAlwaysOnTop(true);

        Image iconImg = loadModIcon();
        if (iconImg != null) {
            frame.setIconImage(iconImg);
        }

        JPanel mainPanel = new JPanel(new BorderLayout(16, 16));
        mainPanel.setBorder(new EmptyBorder(20, 24, 20, 24));

        // Header with AntiRAT logo
        JPanel headerPanel = new JPanel(new BorderLayout(16, 0));
        if (iconImg != null) {
            Image scaled = iconImg.getScaledInstance(56, 56, Image.SCALE_SMOOTH);
            JLabel iconLabel = new JLabel(new ImageIcon(scaled));
            headerPanel.add(iconLabel, BorderLayout.WEST);
        }

        String html = "<html><body style='width: 580px; font-family: sans-serif; font-size: 13px; line-height: 1.4;'>"
                + "<h2 style='color: #c0392b; margin: 0 0 8px 0; font-size: 18px;'>AntiRAT: Token Access Intercepted</h2>"
                + "<p style='margin: 0;'>A mod attempted to read your private Minecraft session token via <b>" + escapeHtml(accessPoint) + "</b>:</p>"
                + "<div style='background-color: #f4f4f4; border-left: 4px solid #c0392b; padding: 12px; margin: 10px 0; font-size: 13px;'>"
                + "<b>Mod ID:</b> <code>" + escapeHtml(modId) + "</code><br>"
                + "<b>Mod File:</b> <code>" + escapeHtml(fileName) + "</code>"
                + "</div>"
                + "<p style='margin: 4px 0 2px 0;'><b>Security Guidance:</b></p>"
                + "<p style='margin: 3px 0;'>• <b>If you are sure you got this mod from a verified site such as Modrinth or CurseForge</b> (e.g. SkyBlockPv, AuthMe) and trust its developers, press <b>Whitelist</b>.</p>"
                + "<p style='margin: 3px 0;'>• <i>You can relaunch your game after whitelisting the mod.</i></p>"
                + "<p style='margin: 3px 0;'>• <b>Otherwise, if you downloaded it from Discord or an untrusted site</b>, delete it immediately to protect your account.</p>"
                + "<p style='color: #27ae60; font-size: 12px; margin-top: 8px;'><i>✓ AntiRAT blocked this request and returned an empty string to protect your account.</i></p>"
                + "</body></html>";

        JLabel label = new JLabel(html);
        headerPanel.add(label, BorderLayout.CENTER);
        mainPanel.add(headerPanel, BorderLayout.CENTER);

        // Buttons with high contrast, legible styling
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 0));
        JButton whitelistBtn = createStyledButton("Whitelist Mod", new Color(225, 240, 255), new Color(24, 90, 157));
        JButton deleteBtn = createStyledButton("Delete Mod File", new Color(255, 235, 235), new Color(180, 40, 30));
        JButton closeBtn = createStyledButton("Keep Blocked / Close", new Color(245, 245, 245), new Color(50, 50, 50));

        whitelistBtn.addActionListener(e -> {
            try {
                Path configDir = Path.of(configDirStr);
                Config.addWhitelist(configDir, modId);
                JOptionPane.showMessageDialog(frame,
                        "Mod '" + modId + "' has been whitelisted in config/antirat.json.\n\nYou can relaunch your game after whitelisting the mod.",
                        "AntiRAT - Whitelisted", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "Failed to save whitelist: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
            frame.dispose();
        });

        deleteBtn.addActionListener(e -> {
            int choice = JOptionPane.showConfirmDialog(frame,
                    "Are you sure you want to permanently delete '" + fileName + "'?",
                    "Confirm Mod Deletion", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) {
                return;
            }

            boolean deleted = false;
            try {
                Path jarPath = originPathStr != null && !originPathStr.isEmpty() ? Path.of(originPathStr) : Path.of("mods", fileName);
                deleted = Files.deleteIfExists(jarPath);
                if (!deleted) {
                    jarPath.toFile().deleteOnExit();
                    Path disabled = jarPath.resolveSibling(jarPath.getFileName().toString() + ".disabled");
                    Files.move(jarPath, disabled);
                    deleted = true;
                }
            } catch (Exception ignored) {}

            if (deleted) {
                JOptionPane.showMessageDialog(frame,
                        "Mod file '" + fileName + "' was successfully deleted from your mods folder.",
                        "AntiRAT - Mod Deleted", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(frame,
                        "Could not delete '" + fileName + "' automatically (file may be in use).\nPlease delete it manually from your mods folder.",
                        "AntiRAT - Warning", JOptionPane.WARNING_MESSAGE);
            }
            frame.dispose();
        });

        closeBtn.addActionListener(e -> frame.dispose());

        buttonPanel.add(whitelistBtn);
        buttonPanel.add(deleteBtn);
        buttonPanel.add(closeBtn);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        frame.getContentPane().add(mainPanel);
        frame.pack();
        frame.setMinimumSize(new Dimension(680, 420));
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private static final class ModThreatItem {
        final String fileName;
        final String filePath;
        final String[] findings;

        ModThreatItem(String fileName, String filePath, String[] findings) {
            this.fileName = fileName;
            this.filePath = filePath;
            this.findings = findings;
        }
    }

    private static void showPreLaunchThreatWindow(String payload, String configDirStr) {
        List<ModThreatItem> items = parsePayload(payload);
        int count = items.size();

        JFrame frame = new JFrame("AntiRAT - Malicious Mod(s) Detected (" + count + " found)");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setAlwaysOnTop(true);

        Image iconImg = loadModIcon();
        if (iconImg != null) {
            frame.setIconImage(iconImg);
        }

        JPanel mainPanel = new JPanel(new BorderLayout(14, 14));
        mainPanel.setBorder(new EmptyBorder(18, 24, 18, 24));

        JPanel headerPanel = new JPanel(new BorderLayout(16, 0));
        if (iconImg != null) {
            Image scaled = iconImg.getScaledInstance(56, 56, Image.SCALE_SMOOTH);
            JLabel iconLabel = new JLabel(new ImageIcon(scaled));
            headerPanel.add(iconLabel, BorderLayout.WEST);
        }

        String titleText = count > 1 ? count + " Malicious Mods Detected!" : "Malicious Mod Detected!";
        String html = "<html><body style='width: 720px; font-family: sans-serif; font-size: 13px; line-height: 1.35;'>"
                + "<h2 style='color: #d32f2f; margin: 0 0 4px 0; font-size: 19px;'>AntiRAT: " + titleText + "</h2>"
                + "<p style='margin: 2px 0;'>AntiRAT static scanner detected token-stealer, dropper, or remote C2 signatures in your mods folder.</p>"
                + "<p style='margin: 4px 0;'><b>Security Guidance:</b><br>"
                + "• If you are sure you got a mod from a verified site such as Modrinth or CurseForge, press <b>Whitelist</b>.<br>"
                + "• <i>You can relaunch your game after whitelisting the mod(s).</i><br>"
                + "• Otherwise, press <b>Delete</b> to permanently remove the file and protect your Microsoft account.</p>"
                + "</body></html>";

        headerPanel.add(new JLabel(html), BorderLayout.CENTER);
        mainPanel.add(headerPanel, BorderLayout.NORTH);

        // List of individual mod threat cards
        JPanel cardsListPanel = new JPanel();
        cardsListPanel.setLayout(new BoxLayout(cardsListPanel, BoxLayout.Y_AXIS));

        List<Runnable> bulkWhitelistActions = new ArrayList<>();
        List<Runnable> bulkDeleteActions = new ArrayList<>();

        for (ModThreatItem item : items) {
            JPanel card = new JPanel(new BorderLayout(12, 8));
            card.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(new Color(210, 210, 210), 1, true),
                    new EmptyBorder(10, 16, 10, 16)
            ));
            card.setBackground(new Color(252, 252, 252));

            // Details
            StringBuilder findingHtml = new StringBuilder();
            findingHtml.append("<html><body style='width: 460px; font-family: sans-serif;'>");
            findingHtml.append("<b style='font-size: 14px; color: #111111;'>📁 ").append(escapeHtml(item.fileName)).append("</b><br>");
            for (String f : item.findings) {
                findingHtml.append("<span style='color: #c0392b; font-size: 12px;'>• ").append(escapeHtml(f)).append("</span><br>");
            }
            findingHtml.append("</body></html>");

            JLabel infoLabel = new JLabel(findingHtml.toString());
            card.add(infoLabel, BorderLayout.CENTER);

            // Row action buttons
            JPanel rowBtnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
            rowBtnPanel.setOpaque(false);

            JLabel statusLabel = new JLabel("Pending");
            statusLabel.setFont(new Font("SansSerif", Font.ITALIC, 12));
            statusLabel.setForeground(new Color(110, 110, 110));

            JButton rowWhitelistBtn = createStyledButton("Whitelist", new Color(225, 240, 255), new Color(24, 90, 157));
            JButton rowDeleteBtn = createStyledButton("Delete", new Color(255, 235, 235), new Color(180, 40, 30));

            Runnable doWhitelist = () -> {
                try {
                    Path configDir = (configDirStr != null && !configDirStr.isEmpty()) ? Path.of(configDirStr) : Path.of("config");
                    String modId = item.fileName.replace(".jar", "");
                    Config.addWhitelist(configDir, item.fileName);
                    Config.addWhitelist(configDir, modId);
                    statusLabel.setText("✓ Whitelisted");
                    statusLabel.setForeground(new Color(24, 90, 157));
                    rowWhitelistBtn.setEnabled(false);
                    rowDeleteBtn.setEnabled(false);
                    card.revalidate();
                    card.repaint();
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            };

            Runnable doDelete = () -> {
                boolean deleted = false;
                try {
                    Path path = item.filePath != null && !item.filePath.isEmpty() ? Path.of(item.filePath) : Path.of("mods", item.fileName);
                    deleted = Files.deleteIfExists(path);
                    if (!deleted) {
                        File f = path.toFile();
                        deleted = f.delete();
                    }
                    if (!deleted && Files.exists(path)) {
                        Path disabled = path.resolveSibling(path.getFileName().toString() + ".disabled");
                        Files.move(path, disabled);
                        deleted = true;
                    }
                } catch (Exception ignored) {}

                if (deleted) {
                    statusLabel.setText("✓ Deleted");
                    statusLabel.setForeground(new Color(180, 40, 30));
                    rowWhitelistBtn.setEnabled(false);
                    rowDeleteBtn.setEnabled(false);
                    card.revalidate();
                    card.repaint();
                } else {
                    statusLabel.setText("Delete failed");
                }
            };

            bulkWhitelistActions.add(doWhitelist);
            bulkDeleteActions.add(doDelete);

            rowWhitelistBtn.addActionListener(e -> {
                doWhitelist.run();
                JOptionPane.showMessageDialog(frame,
                        "Mod '" + item.fileName + "' has been whitelisted.\n\nYou can relaunch your game after whitelisting the mod.",
                        "AntiRAT - Whitelisted", JOptionPane.INFORMATION_MESSAGE);
            });

            rowDeleteBtn.addActionListener(e -> {
                doDelete.run();
                JOptionPane.showMessageDialog(frame,
                        "Mod file '" + item.fileName + "' has been deleted.",
                        "AntiRAT - Mod Deleted", JOptionPane.INFORMATION_MESSAGE);
            });

            rowBtnPanel.add(statusLabel);
            rowBtnPanel.add(rowWhitelistBtn);
            rowBtnPanel.add(rowDeleteBtn);
            card.add(rowBtnPanel, BorderLayout.EAST);

            cardsListPanel.add(card);
            cardsListPanel.add(new JLabel(" ")); // spacing
        }

        JScrollPane scrollPane = new JScrollPane(cardsListPanel);
        scrollPane.setPreferredSize(new Dimension(780, Math.min(380, count * 110 + 30)));
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        // Bottom action buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 0));
        if (count > 1) {
            JButton whitelistAllBtn = createStyledButton("Whitelist All", new Color(225, 240, 255), new Color(24, 90, 157));
            JButton deleteAllBtn = createStyledButton("Delete All", new Color(255, 235, 235), new Color(180, 40, 30));

            whitelistAllBtn.addActionListener(e -> {
                bulkWhitelistActions.forEach(Runnable::run);
                JOptionPane.showMessageDialog(frame,
                        "All mods have been whitelisted.\n\nYou can relaunch your game after whitelisting the mod(s).",
                        "AntiRAT - Whitelisted All", JOptionPane.INFORMATION_MESSAGE);
            });

            deleteAllBtn.addActionListener(e -> {
                bulkDeleteActions.forEach(Runnable::run);
                JOptionPane.showMessageDialog(frame,
                        "All infected mod files have been deleted.",
                        "AntiRAT - Deleted All", JOptionPane.INFORMATION_MESSAGE);
            });

            buttonPanel.add(whitelistAllBtn);
            buttonPanel.add(deleteAllBtn);
        }

        JButton closeBtn = createStyledButton("Close", new Color(245, 245, 245), new Color(50, 50, 50));
        closeBtn.addActionListener(e -> frame.dispose());
        buttonPanel.add(closeBtn);

        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        frame.getContentPane().add(mainPanel);
        frame.pack();
        frame.setMinimumSize(new Dimension(840, 560));
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private static List<ModThreatItem> parsePayload(String payload) {
        List<ModThreatItem> result = new ArrayList<>();
        if (payload == null || payload.isEmpty()) return result;

        String[] reports = payload.split("###");
        for (String rep : reports) {
            String[] parts = rep.split("\\|\\|");
            if (parts.length >= 3) {
                String fileName = parts[0];
                String filePath = parts[1];
                String[] findings = parts[2].split(";;");
                result.add(new ModThreatItem(fileName, filePath, findings));
            } else if (parts.length >= 1) {
                result.add(new ModThreatItem(parts[0], "", new String[]{"Malicious pattern detected"}));
            }
        }
        return result;
    }

    private static JButton createStyledButton(String text, Color background, Color textColor) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("SansSerif", Font.BOLD, 13));
        btn.setForeground(textColor);
        btn.setBackground(background);
        btn.setFocusPainted(false);
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(190, 190, 190), 1, true),
                new EmptyBorder(7, 16, 7, 16)
        ));
        btn.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
        return btn;
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
