package burp;

import com.sun.org.apache.xpath.internal.objects.XString;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane,upSplitPane;
    private static ConfigPanel configPanel;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private static PrintWriter stdout;
    private JPanel jp1,jp2;
    private JScrollPane jsp1,jsp2;
    private JTextArea jta1,jta2;
    //private JLabel jlab1,jlab2,jlab3;
    private Map<String,Map<String,List<String>>> url_map = new HashMap<>();
    //private Map<String,String> js_map = new HashMap<>();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        BurpExtender.stdout = new PrintWriter(callbacks.getStdout(), true);
        BurpExtender.stdout.println("hello burp jsfinder!");
        BurpExtender.stdout.println("author: nannanshen");
        BurpExtender.stdout.println("version:1.0");

        helpers = callbacks.getHelpers();


        callbacks.setExtensionName("Burp Jsfinder");


        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                // 主要面版分割
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);


                upSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                upSplitPane.setEnabled(false); // 禁止拖动
                configPanel = new ConfigPanel();

                Table logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable);
                splitPane.setLeftComponent(scrollPane);

                // 带有请求/响应的标签页
                JTabbedPane tabs = new JTabbedPane();
                jp1=new JPanel();//面板1(选项卡1)
                jp2=new JPanel();//面板2(选项卡2)
                //jp3=new JPanel();//面板2(选项卡2)


                jta1 = newJta("js urls:");
                jta2 = newJta("find links:");
                //jta3 = newJta("find urls:");

                jsp1=new JScrollPane(jta1);
                jsp2=new JScrollPane(jta2);
                //jsp3=new JScrollPane(jta3);

                jp1.setLayout(new BorderLayout());//设置为BorderLayout布局管理器
                jp2.setLayout(new BorderLayout());
                //jp3.setLayout(new BorderLayout());
                jp1.add(jsp1);
                jp2.add(jsp2);
                //jp3.add(jsp3);

                tabs.addTab("js", jp1);//添加选项卡进选项卡面板
                tabs.addTab("urls", jp2);
                //tabs.addTab("选项卡C", jp3);

//                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
//                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
//                tabs.addTab("Request", requestViewer.getComponent());
//                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);
                upSplitPane.add(configPanel, "left");
                upSplitPane.add(scrollPane, "right");

                splitPane.add(upSplitPane, "left");

                // 定制UI组件
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);

                // 在Burp的UI中添加自定义的标签
                callbacks.addSuiteTab(BurpExtender.this);

                //注册HTTP监听
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });
    }

    public JTextArea newJta(String text)
    {
        JTextArea jta=new JTextArea(text,18,1);
        //jta.setLineWrap(true);    //设置文本域中的文本为自动换行
        jta.setForeground(Color.BLACK);    //设置组件的背景色
        jta.setFont(new Font("楷体",Font.BOLD,16));    //修改字体样式
        jta.setBackground(Color.LIGHT_GRAY);    //设置背景色
        jta.setEditable(false);//不可编辑状态
        //jta.setText("");
        //JScrollPane jsp=new JScrollPane(jta);    //将文本域放入滚动窗口
        return jta;
    }



    @Override
    public String getTabCaption()
    {
        //返回标签TAG名称
        return "Burp Jsfinder";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }

    //HTTP监听及相关处理
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        // only process responses
        if (!messageIsRequest && configPanel.getifAutoSend())
        {
            String mime = helpers.analyzeResponse(messageInfo.getResponse()).getInferredMimeType();
            if(mime.equals("script") || mime.equals("HTML")){
                // create a new log entry with the message details
                synchronized(log)
                {
                    String text = new String(messageInfo.getResponse());
                    URL url = helpers.analyzeRequest(messageInfo).getUrl();
                    String url1 = url.getProtocol()+"://"+url.getHost()+":"+url.getPort();
                    int row = log.size();
                    if(!url_map.containsKey(url1)){
                        Map<String,List<String>> js_map = new HashMap<>();
                        url_map.put(url1,js_map);
                        log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                                url1, "passive"));
                        fireTableRowsInserted(row, row);
                    }
                    if(!url_map.get(url1).containsKey(url.toString())){
                        url_map.get(url1).put(url.toString(),findUrl(url,text));
                    }

                }
            }

        }
    }


    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 3;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "Tool";
            case 1:
                return "URL";
            case 2:
                return "Type";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return callbacks.getToolName(logEntry.tool);
            case 1:
                return logEntry.uri;
            case 2:
                return logEntry.type;
            default:
                return "";
        }
    }

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }


    public List<String> findUrl(URL url,String js)
    {
        //String url1 = url.getProtocol()+"://"+url.getHost()+":"+url.getPort();
        String pattern_raw = "(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;|*()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/|;][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')";
        Pattern r = Pattern.compile(pattern_raw);
        Matcher m = r.matcher(js);
        //BurpExtender.stdout.println("statr match");
        int matcher_start = 0;
        List<String> ex_urls = new ArrayList<String>();
        while (m.find(matcher_start)){
            //BurpExtender.stdout.println(m.group(1));
            ex_urls.add(m.group(1).replaceAll("\"","").replaceAll("'","").replaceAll("\n","").replaceAll("\t","").trim());
            matcher_start = m.end();
        }
        LinkedHashSet<String> hashSet = new LinkedHashSet<>(ex_urls);
        ArrayList<String> temp_urls = new ArrayList<>(hashSet);
        List<String> all_urls = new ArrayList<>();
        for(String temp_url:temp_urls){
            all_urls.add(process_url(url, temp_url));
        }
        List<String> result = new ArrayList<String>();
        for(String singerurl:all_urls){
            String domain = url.getHost();
            List<Integer> positions = find_last(domain, ".");
            String maindomain = domain;
            if(positions.size()>1){
                maindomain = domain.substring(positions.get(-2)+1);
            }
            try {
                URL subURL = new URL(singerurl);
                String subdomain = subURL.getHost();
                if(subdomain.contains(maindomain)){
                    if(!result.contains(singerurl)){
                        result.add(singerurl);
                    }

                }

            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }

        }
        return  result;
    }

    public String process_url(URL url ,String re_URL) {
        String black_url = "javascript:";
        String ab_URL = url.getHost() + ":"+ url.getPort();
        String host_URL = url.getProtocol();
        String result = "";
        if (re_URL.length() < 4) {
            if (re_URL.startsWith("//")) {
                result = host_URL + ":" + "//" + ab_URL + re_URL.substring(1);
            } else if (!re_URL.startsWith("//")) {
                if (re_URL.startsWith("/")) {
                    result = host_URL + "://" + ab_URL + re_URL;
                } else {
                    if (re_URL.startsWith(".")) {
                        if (re_URL.startsWith("..")) {
                            result = host_URL + "://" + ab_URL + re_URL.substring(2);
                        } else {
                            result = host_URL + "://" + ab_URL + re_URL.substring(1);
                        }
                    } else {
                        result = host_URL + "://" + ab_URL + "/" + re_URL;
                    }

                }

            }
        } else {
            if (re_URL.startsWith("//")) {
                result = host_URL + ":" + re_URL;
            } else if (re_URL.startsWith("http")) {
                result = re_URL;
            } else if (!re_URL.startsWith("//") && !re_URL.contains(black_url)) {
                if (re_URL.startsWith("/")) {
                    result = host_URL + "://" + ab_URL + re_URL;
                } else {
                    if (re_URL.startsWith(".")) {
                        if (re_URL.startsWith("..")) {
                            result = host_URL + "://" + ab_URL + re_URL.substring(2);
                        } else {
                            result = host_URL + "://" + ab_URL + re_URL.substring(1);
                        }
                    } else {
                        result = host_URL + "://" + ab_URL + "/" + re_URL;
                    }

                }

            } else {
                result = url.toString();
            }
        }

        return result;

    }

    public List<Integer> find_last(String string, String str)
    {
        List<Integer> positions = new ArrayList<Integer>();
        int last_position= -1;
        while(true){
            int position = string.lastIndexOf(str,last_position+1);
            if(position == -1){
                break;
            }
            last_position = position;
            positions.add(position);
        }


        return positions;
    }


    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
//            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
//            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
//            currentlyDisplayedItem = logEntry.requestResponse;
            String uri = logEntry.uri;
            //String js_url = logEntry.url.toString();
            Map<String,List<String>> js_map = url_map.get(uri);
            jta1.setText("");
            jta2.setText("");
            //jta1.append(js_url);
            String bl = configPanel.getBlackList();
            String[] black_lists = bl.split(",");
            if(js_map.size()>0) {
                for (String js_url : js_map.keySet()) {
                    jta1.append(js_url);
                    jta1.append("\n");
                    if(js_map.get(js_url).size()>0){
                        for(String url : js_map.get(js_url)){
                            Boolean isblack = Boolean.FALSE;
                            for(String black : black_lists){
                                if(url.endsWith("."+black)){
                                    isblack = Boolean.TRUE;
                                    break;
                                }
                            }
                            if(!isblack){
                                jta2.append(url);
                                jta2.append("\n");
                            }
                        }
                    }
                }
            }else{
                jta1.append("not found!");
                jta2.append("not found!");
            }

            //jta1.setText(String.valueOf(row));
            //jta1.append("asdf\n");
            //jta1.append("asdf\n");

            super.changeSelection(row, col, toggle, extend);
        }
    }


    private class ConfigPanel extends JToolBar {
        JButton btn1;
        JCheckBox ifAutoSend;
        JTextField bl;
        JLabel blacklist;

        public ConfigPanel() {
            this.btn1=new JButton("清空列表");
            this.ifAutoSend = new JCheckBox("启动插件");
            this.bl = new JTextField("js,css,jpg");
            this.blacklist = new JLabel("   过滤文件名:");

            // 默认不发送
            //this.autoSendRequestCheckBox.setSelected(false);
            this.ifAutoSend.setSelected(true);
            //this.noPassiveCheckBox.setSelected(false);

            // 不可悬浮
            this.setFloatable(false);
            this.add(btn1);
            this.add(ifAutoSend);
            this.add(blacklist);
            this.add(bl);


            btn1.addActionListener(new ActionListener() {//清空列表
                @Override
                public void actionPerformed(ActionEvent e) {
                    log.clear();//清除log的内容
                    url_map.clear();
                    fireTableRowsInserted(0, 0);//刷新列表中的展示
                    jta1.setText("");
                    jta2.setText("");
                }
            });
        }


        public Boolean getifAutoSend() {
            return this.ifAutoSend.isSelected();
        }
        public String  getBlackList() {
            return this.bl.getText().trim();
        }


    }


    private static class LogEntry
    {
        final int tool;
        final IHttpRequestResponsePersisted requestResponse;
        //final URL url;
        //final String mime;
        final String type;
        final String uri;

        LogEntry(int tool, IHttpRequestResponsePersisted requestResponse, String uri ,String type)
        {
            this.tool = tool;
            this.requestResponse = requestResponse;
            //this.url = url;
            //this.mime = mime;
            this.type = type;
            this.uri = uri;
        }

    }

}
