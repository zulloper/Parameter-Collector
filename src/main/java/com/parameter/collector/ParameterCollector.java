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
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;

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
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

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
    
    // 자동 내보내기 설정
    private boolean autoExportEnabled = false;
    private String autoExportPath = "";
    private final Object autoExportLock = new Object();

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
        
        // 내보내기 버튼 추가
        JButton exportButton = new JButton("JSON 내보내기");
        exportButton.addActionListener(e -> exportToJson());
        
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(searchField, BorderLayout.CENTER);
        bottomPanel.add(exportButton, BorderLayout.EAST);
        
        JPanel paramPanel = new JPanel(new BorderLayout());
        paramPanel.add(new JScrollPane(paramTable), BorderLayout.CENTER);
        paramPanel.add(bottomPanel, BorderLayout.SOUTH);
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
        
        // 자동 내보내기 설정 추가
        JCheckBox autoExportCheckBox = new JCheckBox("자동 내보내기 활성화", autoExportEnabled);
        JTextField autoExportPathField = new JTextField(autoExportPath);
        JButton browseButton = new JButton("경로 선택...");
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
            fileChooser.setSelectedFile(new File(autoExportPath.isEmpty() ? "parameters_auto.json" : autoExportPath));
            if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                if (!file.getName().endsWith(".json")) {
                    file = new File(file.getAbsolutePath() + ".json");
                }
                autoExportPathField.setText(file.getAbsolutePath());
            }
        });
        
        JPanel autoExportPanel = new JPanel(new BorderLayout());
        autoExportPanel.add(autoExportPathField, BorderLayout.CENTER);
        autoExportPanel.add(browseButton, BorderLayout.EAST);
        
        panel.add(new JLabel("최대 파라미터 이름 길이:"));
        panel.add(nameLenField);
        panel.add(new JLabel("최대 파라미터 값 길이:"));
        panel.add(valueLenField);
        panel.add(new JLabel("필터링 키워드(비우면 전체):"));
        panel.add(filterField);
        panel.add(new JLabel(""));
        panel.add(autoExportCheckBox);
        panel.add(new JLabel("자동 내보내기 경로:"));
        panel.add(autoExportPanel);
        
        int result = JOptionPane.showConfirmDialog(null, panel, "Parameter Collector 설정", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            try {
                maxParamNameLength = Integer.parseInt(nameLenField.getText());
                maxParamValueLength = Integer.parseInt(valueLenField.getText());
                filterKeyword = filterField.getText();
                autoExportEnabled = autoExportCheckBox.isSelected();
                autoExportPath = autoExportPathField.getText();
                
                // 자동 내보내기가 활성화되고 경로가 설정되어 있으면 초기 저장
                if (autoExportEnabled && !autoExportPath.isEmpty()) {
                    performAutoExport();
                }
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
            CopyOnWriteArrayList<String> values = parameterValues.computeIfAbsent(paramName, k -> new CopyOnWriteArrayList<>());
            // 중복 체크 후 추가
            if (!values.contains(paramValue)) {
                values.add(paramValue);
                updateResultTabs();
                
                // 자동 내보내기 수행
                if (autoExportEnabled && !autoExportPath.isEmpty()) {
                    // 별도 스레드에서 실행하여 성능 영향 최소화
                    new Thread(() -> performAutoExport()).start();
                }
            }
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
    
    private void exportToJson() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
        fileChooser.setSelectedFile(new File("parameters.json"));
        
        int result = fileChooser.showSaveDialog(null);
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            if (!file.getName().endsWith(".json")) {
                file = new File(file.getAbsolutePath() + ".json");
            }
            
            try {
                JsonArray exportData = createExportData();
                JsonArray existingData = new JsonArray();
                
                // 기존 파일이 있으면 읽어서 중복 체크
                if (file.exists()) {
                    try (FileReader reader = new FileReader(file)) {
                        JsonElement element = JsonParser.parseReader(reader);
                        if (element.isJsonArray()) {
                            existingData = element.getAsJsonArray();
                        }
                    }
                }
                
                // 중복되지 않는 항목만 추가
                JsonArray mergedData = mergeJsonData(existingData, exportData);
                
                // 파일에 저장
                try (FileWriter writer = new FileWriter(file)) {
                    Gson gson = new GsonBuilder().setPrettyPrinting().create();
                    gson.toJson(mergedData, writer);
                }
                
                JOptionPane.showMessageDialog(null, "JSON 파일이 성공적으로 저장되었습니다.");
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, "파일 저장 중 오류 발생: " + e.getMessage(), "오류", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    private JsonArray createExportData() {
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
        return result;
    }
    
    private JsonArray mergeJsonData(JsonArray existing, JsonArray newData) {
        Map<String, CopyOnWriteArrayList<String>> mergedMap = new HashMap<>();
        
        // 기존 데이터를 맵에 추가
        for (JsonElement element : existing) {
            JsonObject obj = element.getAsJsonObject();
            String name = obj.get("name").getAsString();
            JsonArray values = obj.get("values").getAsJsonArray();
            CopyOnWriteArrayList<String> valueList = mergedMap.computeIfAbsent(name, k -> new CopyOnWriteArrayList<>());
            for (JsonElement value : values) {
                String val = value.getAsString();
                if (!valueList.contains(val)) {
                    valueList.add(val);
                }
            }
        }
        
        // 새 데이터를 맵에 추가 (중복 체크)
        for (JsonElement element : newData) {
            JsonObject obj = element.getAsJsonObject();
            String name = obj.get("name").getAsString();
            JsonArray values = obj.get("values").getAsJsonArray();
            CopyOnWriteArrayList<String> valueList = mergedMap.computeIfAbsent(name, k -> new CopyOnWriteArrayList<>());
            for (JsonElement value : values) {
                String val = value.getAsString();
                if (!valueList.contains(val)) {
                    valueList.add(val);
                }
            }
        }
        
        // 맵을 다시 JsonArray로 변환
        JsonArray result = new JsonArray();
        for (Map.Entry<String, CopyOnWriteArrayList<String>> entry : mergedMap.entrySet()) {
            JsonObject paramObj = new JsonObject();
            paramObj.addProperty("name", entry.getKey());
            JsonArray valuesArray = new JsonArray();
            for (String value : entry.getValue()) {
                valuesArray.add(value);
            }
            paramObj.add("values", valuesArray);
            result.add(paramObj);
        }
        
        return result;
    }
    
    private void performAutoExport() {
        synchronized (autoExportLock) {
            try {
                File file = new File(autoExportPath);
                JsonArray exportData = createExportData();
                JsonArray existingData = new JsonArray();
                
                // 기존 파일이 있으면 읽어서 중복 체크
                if (file.exists()) {
                    try (FileReader reader = new FileReader(file)) {
                        JsonElement element = JsonParser.parseReader(reader);
                        if (element.isJsonArray()) {
                            existingData = element.getAsJsonArray();
                        }
                    }
                }
                
                // 중복되지 않는 항목만 추가
                JsonArray mergedData = mergeJsonData(existingData, exportData);
                
                // 파일에 저장
                try (FileWriter writer = new FileWriter(file)) {
                    Gson gson = new GsonBuilder().setPrettyPrinting().create();
                    gson.toJson(mergedData, writer);
                }
                
                api.logging().logToOutput("[Parameter Collector] 자동 내보내기 완료: " + autoExportPath);
            } catch (IOException e) {
                api.logging().logToError("[Parameter Collector] 자동 내보내기 실패: " + e.getMessage());
            }
        }
    }
} 