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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
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

    // 민감 파라미터 필터링 설정
    private static final Set<String> DEFAULT_SENSITIVE_KEYWORDS = Set.of(
        "password", "pass", "passwd", "pwd", "secret", "token",
        "key", "credential", "auth", "api_key", "apikey",
        "access_token", "refresh_token", "private_key"
    );
    private Set<String> sensitiveKeywords = new HashSet<>(DEFAULT_SENSITIVE_KEYWORDS);
    private boolean enableSensitiveFilter = true;

    // 바이너리 Content-Type 목록
    private static final Set<String> BINARY_CONTENT_TYPE_PREFIXES = Set.of(
        "image/", "audio/", "video/", "font/"
    );
    private static final Set<String> BINARY_CONTENT_TYPES = Set.of(
        "application/octet-stream", "application/pdf", "application/zip",
        "application/x-tar", "application/gzip", "application/x-rar-compressed"
    );

    // 헤더 수집 설정
    private static final Set<String> DEFAULT_COLLECTABLE_HEADERS = Set.of(
        "Authorization", "X-Auth-Token", "X-API-Key",
        "X-Access-Token", "X-CSRF-Token", "X-Request-Id"
    );
    private Set<String> collectableHeaders = new HashSet<>(DEFAULT_COLLECTABLE_HEADERS);
    private boolean enableHeaderCollection = true;
    private boolean enableCookieCollection = true;

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
        JTabbedPane settingsTabs = new JTabbedPane();

        // === 탭 1: 기본 설정 ===
        JPanel basicPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JTextField nameLenField = new JTextField(String.valueOf(maxParamNameLength), 10);
        JTextField valueLenField = new JTextField(String.valueOf(maxParamValueLength), 10);
        JTextField filterField = new JTextField(filterKeyword, 20);

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        basicPanel.add(new JLabel("최대 파라미터 이름 길이:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        basicPanel.add(nameLenField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        basicPanel.add(new JLabel("최대 파라미터 값 길이:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        basicPanel.add(valueLenField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        basicPanel.add(new JLabel("필터링 키워드 (비우면 전체):"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        basicPanel.add(filterField, gbc);

        // 여백 추가
        gbc.gridx = 0; gbc.gridy = 3; gbc.weighty = 1;
        basicPanel.add(new JLabel(""), gbc);

        settingsTabs.addTab("기본", basicPanel);

        // === 탭 2: 민감 파라미터 설정 ===
        JPanel sensitivePanel = new JPanel(new BorderLayout(5, 5));
        sensitivePanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JCheckBox sensitiveFilterCheckBox = new JCheckBox("민감 파라미터 필터링 활성화", enableSensitiveFilter);
        JTextArea sensitiveKeywordsArea = new JTextArea(String.join("\n", sensitiveKeywords), 10, 30);
        sensitiveKeywordsArea.setLineWrap(true);
        JButton resetSensitiveBtn = new JButton("기본값 복원");
        resetSensitiveBtn.addActionListener(e -> {
            sensitiveKeywordsArea.setText(String.join("\n", DEFAULT_SENSITIVE_KEYWORDS));
        });

        JPanel sensitiveTopPanel = new JPanel(new BorderLayout());
        sensitiveTopPanel.add(sensitiveFilterCheckBox, BorderLayout.WEST);

        JPanel sensitiveBottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        sensitiveBottomPanel.add(resetSensitiveBtn);

        sensitivePanel.add(sensitiveTopPanel, BorderLayout.NORTH);
        sensitivePanel.add(new JLabel("제외할 키워드 (줄바꿈으로 구분):"), BorderLayout.WEST);
        sensitivePanel.add(new JScrollPane(sensitiveKeywordsArea), BorderLayout.CENTER);
        sensitivePanel.add(sensitiveBottomPanel, BorderLayout.SOUTH);

        settingsTabs.addTab("민감 파라미터", sensitivePanel);

        // === 탭 3: 헤더 수집 설정 ===
        JPanel headerPanel = new JPanel(new BorderLayout(5, 5));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JCheckBox cookieCheckBox = new JCheckBox("쿠키 수집 활성화", enableCookieCollection);
        JCheckBox headerCheckBox = new JCheckBox("인증 헤더 수집 활성화", enableHeaderCollection);
        JTextArea headerListArea = new JTextArea(String.join("\n", collectableHeaders), 8, 30);
        headerListArea.setLineWrap(true);
        JButton resetHeaderBtn = new JButton("기본값 복원");
        resetHeaderBtn.addActionListener(e -> {
            headerListArea.setText(String.join("\n", DEFAULT_COLLECTABLE_HEADERS));
        });

        JPanel headerCheckBoxPanel = new JPanel(new GridLayout(2, 1));
        headerCheckBoxPanel.add(cookieCheckBox);
        headerCheckBoxPanel.add(headerCheckBox);

        JPanel headerBottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        headerBottomPanel.add(resetHeaderBtn);

        JPanel headerCenterPanel = new JPanel(new BorderLayout(5, 5));
        headerCenterPanel.add(new JLabel("수집할 헤더 목록 (줄바꿈으로 구분):"), BorderLayout.NORTH);
        headerCenterPanel.add(new JScrollPane(headerListArea), BorderLayout.CENTER);

        headerPanel.add(headerCheckBoxPanel, BorderLayout.NORTH);
        headerPanel.add(headerCenterPanel, BorderLayout.CENTER);
        headerPanel.add(headerBottomPanel, BorderLayout.SOUTH);

        settingsTabs.addTab("헤더 수집", headerPanel);

        // === 탭 4: 자동 내보내기 설정 ===
        JPanel autoExportTabPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc2 = new GridBagConstraints();
        gbc2.insets = new Insets(5, 5, 5, 5);
        gbc2.fill = GridBagConstraints.HORIZONTAL;

        JCheckBox autoExportCheckBox = new JCheckBox("자동 내보내기 활성화", autoExportEnabled);
        JTextField autoExportPathField = new JTextField(autoExportPath, 25);
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

        gbc2.gridx = 0; gbc2.gridy = 0; gbc2.gridwidth = 2;
        autoExportTabPanel.add(autoExportCheckBox, gbc2);

        gbc2.gridx = 0; gbc2.gridy = 1; gbc2.gridwidth = 1; gbc2.weightx = 0;
        autoExportTabPanel.add(new JLabel("저장 경로:"), gbc2);
        gbc2.gridx = 1; gbc2.weightx = 1;
        autoExportTabPanel.add(autoExportPathField, gbc2);

        gbc2.gridx = 0; gbc2.gridy = 2; gbc2.gridwidth = 2; gbc2.weightx = 0;
        JPanel browsePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        browsePanel.add(browseButton);
        autoExportTabPanel.add(browsePanel, gbc2);

        // 여백 추가
        gbc2.gridx = 0; gbc2.gridy = 3; gbc2.weighty = 1;
        autoExportTabPanel.add(new JLabel(""), gbc2);

        settingsTabs.addTab("자동 내보내기", autoExportTabPanel);

        // === 다이얼로그 표시 ===
        settingsTabs.setPreferredSize(new Dimension(450, 350));
        int result = JOptionPane.showConfirmDialog(null, settingsTabs,
            "Parameter Collector 설정", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            try {
                // 기본 설정 적용
                maxParamNameLength = Integer.parseInt(nameLenField.getText());
                maxParamValueLength = Integer.parseInt(valueLenField.getText());
                filterKeyword = filterField.getText();

                // 민감 파라미터 설정 적용
                enableSensitiveFilter = sensitiveFilterCheckBox.isSelected();
                sensitiveKeywords = Arrays.stream(sensitiveKeywordsArea.getText().split("\n"))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toCollection(HashSet::new));

                // 헤더 수집 설정 적용
                enableCookieCollection = cookieCheckBox.isSelected();
                enableHeaderCollection = headerCheckBox.isSelected();
                collectableHeaders = Arrays.stream(headerListArea.getText().split("\n"))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toCollection(HashSet::new));

                // 자동 내보내기 설정 적용
                autoExportEnabled = autoExportCheckBox.isSelected();
                autoExportPath = autoExportPathField.getText();

                // 자동 내보내기가 활성화되고 경로가 설정되어 있으면 초기 저장
                if (autoExportEnabled && !autoExportPath.isEmpty()) {
                    performAutoExport();
                }

                api.logging().logToOutput("[Parameter Collector] 설정이 저장되었습니다.");
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(null, "숫자를 올바르게 입력하세요.", "오류", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private class HttpHandler implements burp.api.montoya.http.handler.HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            String contentType = getContentType(requestToBeSent);

            // 바이너리 요청은 스킵
            if (isBinaryContentType(contentType)) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            String url = requestToBeSent.url();
            String body = requestToBeSent.bodyToString();

            // URL 파라미터 추출
            extractParametersFromUrl(url);

            // Body 파라미터 추출 (Content-Type 기반 분기)
            extractParametersFromBody(body, contentType);

            // 쿠키 추출
            extractCookieParameters(requestToBeSent);

            // 인증 헤더 추출
            extractHeaderParameters(requestToBeSent);

            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // === 유틸리티 메서드 ===

        private String getContentType(HttpRequestToBeSent request) {
            String contentType = request.headerValue("Content-Type");
            return contentType != null ? contentType.toLowerCase() : "";
        }

        private boolean isBinaryContentType(String contentType) {
            if (contentType == null || contentType.isEmpty()) {
                return false;
            }
            String lower = contentType.toLowerCase();

            // 접두사 기반 체크 (image/*, audio/*, video/*, font/*)
            for (String prefix : BINARY_CONTENT_TYPE_PREFIXES) {
                if (lower.startsWith(prefix)) {
                    return true;
                }
            }

            // 특정 바이너리 타입 체크
            for (String binaryType : BINARY_CONTENT_TYPES) {
                if (lower.contains(binaryType)) {
                    return true;
                }
            }
            return false;
        }

        private boolean isSensitiveParameter(String paramName) {
            if (!enableSensitiveFilter || paramName == null) {
                return false;
            }
            String lowerName = paramName.toLowerCase();
            for (String keyword : sensitiveKeywords) {
                if (lowerName.contains(keyword.toLowerCase())) {
                    return true;
                }
            }
            return false;
        }

        // === URL 파라미터 추출 ===

        private void extractParametersFromUrl(String url) {
            Pattern pattern = Pattern.compile("[?&]([^=&]+)=([^&]*)");
            Matcher matcher = pattern.matcher(url);
            while (matcher.find()) {
                String paramName = matcher.group(1);
                String paramValue = matcher.group(2);
                addParameterValue(paramName, paramValue);
            }
        }

        // === Body 파라미터 추출 (Content-Type 기반 분기) ===

        private void extractParametersFromBody(String body, String contentType) {
            if (body == null || body.trim().isEmpty()) {
                return;
            }

            if (contentType.contains("application/json")) {
                extractJsonParameters(body);
            } else if (contentType.contains("multipart/form-data")) {
                extractMultipartParameters(body, contentType);
            } else {
                // 기본값: form-urlencoded 또는 알 수 없는 타입
                extractFormUrlEncoded(body);
            }
        }

        private void extractFormUrlEncoded(String body) {
            Pattern pattern = Pattern.compile("([^=&]+)=([^&]*)");
            Matcher matcher = pattern.matcher(body);
            while (matcher.find()) {
                String paramName = matcher.group(1);
                String paramValue = matcher.group(2);
                addParameterValue(paramName, paramValue);
            }
        }

        // === JSON 파싱 ===

        private void extractJsonParameters(String body) {
            if (body == null || body.trim().isEmpty()) {
                return;
            }
            try {
                JsonElement element = JsonParser.parseString(body);
                extractJsonElement("", element);
            } catch (Exception e) {
                api.logging().logToError("[Parameter Collector] JSON 파싱 실패: " + e.getMessage());
            }
        }

        private void extractJsonElement(String prefix, JsonElement element) {
            if (element == null || element.isJsonNull()) {
                return;
            }

            if (element.isJsonObject()) {
                JsonObject obj = element.getAsJsonObject();
                for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                    String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
                    extractJsonElement(key, entry.getValue());
                }
            } else if (element.isJsonArray()) {
                JsonArray array = element.getAsJsonArray();
                for (int i = 0; i < array.size(); i++) {
                    String key = prefix + "[" + i + "]";
                    extractJsonElement(key, array.get(i));
                }
            } else if (element.isJsonPrimitive()) {
                String value = element.getAsString();
                addParameterValue(prefix, value);
            }
        }

        // === Multipart 파싱 ===

        private void extractMultipartParameters(String body, String contentType) {
            String boundary = extractBoundary(contentType);
            if (boundary == null || body == null) {
                return;
            }

            String[] parts = body.split("--" + Pattern.quote(boundary));
            for (String part : parts) {
                if (part.trim().isEmpty() || part.trim().equals("--")) {
                    continue;
                }
                parseMultipartPart(part);
            }
        }

        private String extractBoundary(String contentType) {
            Pattern pattern = Pattern.compile("boundary=([^;\\s]+)", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(contentType);
            if (matcher.find()) {
                String boundary = matcher.group(1).trim();
                // 따옴표 제거
                if (boundary.startsWith("\"") && boundary.endsWith("\"")) {
                    boundary = boundary.substring(1, boundary.length() - 1);
                }
                return boundary;
            }
            return null;
        }

        private void parseMultipartPart(String part) {
            Pattern dispositionPattern = Pattern.compile(
                "Content-Disposition:\\s*form-data;\\s*name=\"([^\"]+)\"(?:;\\s*filename=\"([^\"]+)\")?",
                Pattern.CASE_INSENSITIVE
            );
            Matcher matcher = dispositionPattern.matcher(part);

            if (matcher.find()) {
                String name = matcher.group(1);
                String filename = matcher.group(2);

                if (filename != null) {
                    // 파일 업로드: 파일명만 기록
                    addParameterValue(name, "[FILE: " + filename + "]");
                } else {
                    // 일반 필드: 값 추출
                    // 헤더와 본문은 빈 줄로 구분
                    int headerEnd = part.indexOf("\r\n\r\n");
                    if (headerEnd == -1) {
                        headerEnd = part.indexOf("\n\n");
                    }
                    if (headerEnd != -1) {
                        String value = part.substring(headerEnd).trim();
                        // Content-Type 체크 (바이너리 파트 무시)
                        if (!isPartBinary(part)) {
                            addParameterValue(name, value);
                        }
                    }
                }
            }
        }

        private boolean isPartBinary(String part) {
            Pattern contentTypePattern = Pattern.compile(
                "Content-Type:\\s*([^\\r\\n]+)",
                Pattern.CASE_INSENSITIVE
            );
            Matcher matcher = contentTypePattern.matcher(part);
            if (matcher.find()) {
                String partContentType = matcher.group(1).trim();
                return isBinaryContentType(partContentType);
            }
            return false;
        }

        // === 쿠키 추출 ===

        private void extractCookieParameters(HttpRequestToBeSent request) {
            if (!enableCookieCollection) {
                return;
            }

            String cookieHeader = request.headerValue("Cookie");
            if (cookieHeader == null || cookieHeader.isEmpty()) {
                return;
            }

            String[] cookies = cookieHeader.split(";");
            for (String cookie : cookies) {
                String[] parts = cookie.trim().split("=", 2);
                if (parts.length == 2) {
                    String name = "[Cookie] " + parts[0].trim();
                    String value = parts[1].trim();
                    addParameterValue(name, value);
                }
            }
        }

        // === 인증 헤더 추출 ===

        private void extractHeaderParameters(HttpRequestToBeSent request) {
            if (!enableHeaderCollection) {
                return;
            }

            // Authorization 헤더 처리
            String authHeader = request.headerValue("Authorization");
            if (authHeader != null && !authHeader.isEmpty()) {
                String[] parts = authHeader.split("\\s+", 2);
                if (parts.length == 2) {
                    addParameterValue("[Header] Authorization-Type", parts[0]);
                    addParameterValue("[Header] Authorization-Value", parts[1]);
                } else {
                    addParameterValue("[Header] Authorization", authHeader);
                }
            }

            // 커스텀 인증 헤더들
            for (String headerName : collectableHeaders) {
                if (headerName.equalsIgnoreCase("Authorization")) {
                    continue; // 이미 처리함
                }
                String headerValue = request.headerValue(headerName);
                if (headerValue != null && !headerValue.isEmpty()) {
                    addParameterValue("[Header] " + headerName, headerValue);
                }
            }
        }

        // === 파라미터 저장 ===

        private void addParameterValue(String paramName, String paramValue) {
            // 민감 파라미터 체크
            if (isSensitiveParameter(paramName)) {
                return;
            }

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