package com.parameter.collector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.ui.menu.Menu;
import burp.api.montoya.ui.menu.MenuItem;
import burp.api.montoya.ui.menu.BasicMenuItem;
import burp.api.montoya.ui.menu.MenuBar;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.core.ByteArray;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import javax.swing.TransferHandler;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.Toolkit;
import javax.swing.JPopupMenu;
import javax.swing.JMenuItem;

public class ParameterCollector implements BurpExtension {
    private MontoyaApi api;
    private ConcurrentHashMap<String, CopyOnWriteArrayList<String>> parameterValues;
    private RawEditor paramEditor;
    private JTabbedPane resultTabs;
    private JTextArea jsonArea;
    private JTable paramTable;
    private JTextField searchField;

    // 옵션: 인스턴스 변수로 변경
    private int maxParamNameLength = 30;
    private int maxParamValueLength = 100;
    private String filterKeyword = "";

    @Override
    public void initialize(MontoyaApi api) {
        System.out.println("[ParameterCollector] initialize() called");
        this.api = api;
        this.parameterValues = new ConcurrentHashMap<>();
        System.out.println("[ParameterCollector] parameterValues map initialized");
        
        // Set extension name
        api.extension().setName("Parameter Collector");

        // Register HTTP request handler
        api.http().registerHttpHandler(new HttpHandler());

        // Prepare the editor for showing parameters
        paramEditor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY, EditorOptions.WRAP_LINES);
        System.out.println("[ParameterCollector] RawEditor created");

        // JTabbedPane 및 각 탭 컴포넌트 생성
        resultTabs = new JTabbedPane();
        jsonArea = new JTextArea();
        jsonArea.setEditable(false);
        paramTable = new JTable();
        paramTable.setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        paramTable.setFocusable(true);
        paramTable.setDragEnabled(true);
        // 우클릭 메뉴(복사/삭제)
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("복사");
        copyItem.addActionListener(e -> {
            int row = paramTable.getSelectedRow();
            int col = paramTable.getSelectedColumn();
            if (row >= 0 && col >= 0) {
                String value = String.valueOf(paramTable.getValueAt(row, col));
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(value), null);
            }
        });
        JMenuItem deleteItem = new JMenuItem("삭제");
        deleteItem.addActionListener(e -> {
            int[] rows = paramTable.getSelectedRows();
            for (int i = rows.length - 1; i >= 0; i--) {
                int row = rows[i];
                String param = (String) paramTable.getValueAt(row, 0);
                String value = (String) paramTable.getValueAt(row, 1);
                CopyOnWriteArrayList<String> values = parameterValues.get(param);
                if (values != null) {
                    values.remove(value);
                    if (values.isEmpty()) parameterValues.remove(param);
                }
            }
            updateParamTabWithSearch();
        });
        popupMenu.add(copyItem);
        popupMenu.add(deleteItem);
        paramTable.setComponentPopupMenu(popupMenu);
        // DELETE 키로 삭제
        paramTable.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke("DELETE"), "deleteRow");
        paramTable.getActionMap().put("deleteRow", new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                int[] rows = paramTable.getSelectedRows();
                for (int i = rows.length - 1; i >= 0; i--) {
                    int row = rows[i];
                    String param = (String) paramTable.getValueAt(row, 0);
                    String value = (String) paramTable.getValueAt(row, 1);
                    CopyOnWriteArrayList<String> values = parameterValues.get(param);
                    if (values != null) {
                        values.remove(value);
                        if (values.isEmpty()) parameterValues.remove(param);
                    }
                }
                updateParamTabWithSearch();
            }
        });

        // 검색창 추가
        searchField = new JTextField();
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { updateParamTabWithSearch(); }
            public void removeUpdate(DocumentEvent e) { updateParamTabWithSearch(); }
            public void changedUpdate(DocumentEvent e) { updateParamTabWithSearch(); }
        });
        JPanel paramPanel = new JPanel(new BorderLayout());
        paramPanel.add(new JScrollPane(paramTable), BorderLayout.CENTER);
        paramPanel.add(searchField, BorderLayout.SOUTH);
        resultTabs.addTab("파라미터", paramPanel);
        resultTabs.addTab("JSON", new JScrollPane(jsonArea));
        resultTabs.addChangeListener(e -> {
            int idx = resultTabs.getSelectedIndex();
            String title = resultTabs.getTitleAt(idx);
            if ("JSON".equals(title)) {
                updateJsonTab();
            } else if ("파라미터".equals(title)) {
                updateParamTabWithSearch();
            }
        });

        // Burp 탭 등록
        JPanel tabPanel = new JPanel(new BorderLayout());
        tabPanel.add(resultTabs, BorderLayout.CENTER);
        tabPanel.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentShown(java.awt.event.ComponentEvent e) {
                int idx = resultTabs.getSelectedIndex();
                String title = resultTabs.getTitleAt(idx);
                if ("JSON".equals(title)) {
                    updateJsonTab();
                } else if ("파라미터".equals(title)) {
                    updateParamTabWithSearch();
                }
            }
        });
        api.userInterface().registerSuiteTab("Collected Parameters", tabPanel);
        System.out.println("[ParameterCollector] Suite tab registered");

        // Add menu item to show collected parameters
        Menu menu = Menu.menu("Parameter Collector")
            .withMenuItems(
                BasicMenuItem.basicMenuItem("Show Collected Parameters").withAction(this::updateResultTabs),
                BasicMenuItem.basicMenuItem("설정").withAction(this::showSettingsDialog)
            );
        api.userInterface().menuBar().registerMenu(menu);
        System.out.println("[ParameterCollector] Menu registered");
    }

    private void updateJsonTab() {
        SwingUtilities.invokeLater(() -> {
            JsonArray result = new JsonArray();
            for (Map.Entry<String, CopyOnWriteArrayList<String>> entry : parameterValues.entrySet()) {
                if (!filterKeyword.isEmpty() && !entry.getKey().contains(filterKeyword)) continue;
                JsonObject paramObj = new JsonObject();
                paramObj.addProperty("name", entry.getKey());
                JsonArray valuesArray = new JsonArray();
                for (String value : entry.getValue()) {
                    if (!filterKeyword.isEmpty() && !value.contains(filterKeyword)) continue;
                    valuesArray.add(value);
                }
                paramObj.add("values", valuesArray);
                result.add(paramObj);
            }
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            jsonArea.setText(gson.toJson(result));
        });
    }

    private void updateParamTab() {
        SwingUtilities.invokeLater(() -> {
            DefaultTableModel paramModel = new DefaultTableModel(new Object[]{"파라미터명", "값"}, 0);
            for (Map.Entry<String, CopyOnWriteArrayList<String>> entry : parameterValues.entrySet()) {
                if (!filterKeyword.isEmpty() && !entry.getKey().contains(filterKeyword)) continue;
                for (String value : entry.getValue()) {
                    if (!filterKeyword.isEmpty() && !value.contains(filterKeyword)) continue;
                    paramModel.addRow(new Object[]{entry.getKey(), value});
                }
            }
            paramTable.setModel(paramModel);
        });
    }

    private void updateParamTabWithSearch() {
        SwingUtilities.invokeLater(() -> {
            String search = searchField.getText().trim();
            DefaultTableModel paramModel = new DefaultTableModel(new Object[]{"파라미터명", "값"}, 0);
            for (Map.Entry<String, CopyOnWriteArrayList<String>> entry : parameterValues.entrySet()) {
                if (!filterKeyword.isEmpty() && !entry.getKey().contains(filterKeyword)) continue;
                for (String value : entry.getValue()) {
                    if (!filterKeyword.isEmpty() && !value.contains(filterKeyword)) continue;
                    if (search.isEmpty() || entry.getKey().contains(search) || value.contains(search)) {
                        paramModel.addRow(new Object[]{entry.getKey(), value});
                    }
                }
            }
            paramTable.setModel(paramModel);
        });
    }

    private void showSettingsDialog() {
        JPanel panel = new JPanel(new GridLayout(0, 1));
        JTextField nameLenField = new JTextField(String.valueOf(maxParamNameLength));
        JTextField valueLenField = new JTextField(String.valueOf(maxParamValueLength));
        JTextField filterField = new JTextField(filterKeyword);
        panel.add(new JLabel("최대 파라미터 이름 길이:"));
        panel.add(nameLenField);
        panel.add(new JLabel("최대 파라미터 값 길이:"));
        panel.add(valueLenField);
        panel.add(new JLabel("필터링 키워드(비우면 전체):"));
        panel.add(filterField);
        int result = JOptionPane.showConfirmDialog(null, panel, "Parameter Collector 설정", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            try {
                maxParamNameLength = Integer.parseInt(nameLenField.getText());
                maxParamValueLength = Integer.parseInt(valueLenField.getText());
                filterKeyword = filterField.getText();
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(null, "숫자를 올바르게 입력하세요.");
            }
        }
    }

    private class HttpHandler implements burp.api.montoya.http.handler.HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            String url = requestToBeSent.url();
            String body = requestToBeSent.bodyToString();
            extractParametersFromUrl(url);
            extractParametersFromBody(body);
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        private void extractParametersFromUrl(String url) {
            Pattern pattern = Pattern.compile("[?&]([^=&]+)=([^&]*)");
            Matcher matcher = pattern.matcher(url);
            while (matcher.find()) {
                String paramName = matcher.group(1);
                String paramValue = matcher.group(2);
                addParameterValue(paramName, paramValue);
            }
        }

        private void extractParametersFromBody(String body) {
            Pattern pattern = Pattern.compile("([^=&]+)=([^&]*)");
            Matcher matcher = pattern.matcher(body);
            while (matcher.find()) {
                String paramName = matcher.group(1);
                String paramValue = matcher.group(2);
                addParameterValue(paramName, paramValue);
            }
        }

        private void addParameterValue(String paramName, String paramValue) {
            if (paramName.length() > maxParamNameLength) {
                paramName = paramName.substring(0, maxParamNameLength) + "...";
            }
            if (paramValue.length() > maxParamValueLength) {
                paramValue = paramValue.substring(0, maxParamValueLength) + "...";
            }
            parameterValues.computeIfAbsent(paramName, k -> new CopyOnWriteArrayList<>()).add(paramValue);
            updateResultTabs();
        }
    }

    private void updateResultTabs() {
        int idx = resultTabs.getSelectedIndex();
        String title = resultTabs.getTitleAt(idx);
        if ("JSON".equals(title)) {
            updateJsonTab();
        } else if ("파라미터".equals(title)) {
            updateParamTabWithSearch();
        }
    }
} 