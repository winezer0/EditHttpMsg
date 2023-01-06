package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender,IHttpListener{
    public static  BurpExtender burpExtender;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;

    public static String ExtenderName;
    public static String ExtenderVersion;

    //规则替换变量
    private String exact_path = null;
    private String exact_old_string = "";
    private String exact_new_string = "";
    private Boolean rough_replace = false;
    private String rough_old_string = "";
    private String rough_new_string = "";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.burpExtender = this;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        ReadConfigYaml(callbacks); //读取配置
        ShowConfigYaml(); //输出配置
        SPLIT_RULE(); //加载时分割规则
        this.ExtenderName= Config.EXTENSION_NAME;
        this.ExtenderVersion = Config.EXTENSION_VERSION;
        callbacks.setExtensionName(ExtenderName + "_" + ExtenderVersion);
        callbacks.registerHttpListener(this);  //注册代理监听器
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        //修改数据并进行发送
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY){
            if (messageIsRequest) { //对请求包进行处理
                IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);

                //获取HOST
                String req_host = messageInfo.getHttpService().getHost();
                //白名单HOST匹配 //未输入时继续处理
                if (!Utils.isMatchKeywords(Config.WHITE_HOST_REGX, req_host, true)) {
                    return;
                }

                //黑名单HOST匹配 //未输入时继续处理
                if (Utils.isMatchKeywords(Config.BLACK_HOST_REGX, req_host, false)) {
                    return;
                }

                //获取请求路径
                String req_path = analyzeRequest.getUrl().getPath();

                //白名单PATH匹配  //未输入时继续处理
                if (!Utils.isMatchKeywords(Config.WHITE_PATH_REGX, req_host, true)) {
                    return;
                }

                //黑名单路径匹配 //未输入时继续处理
                if (Utils.isMatchKeywords(Config.BLACK_PATH_REGX, req_path, false)) {
                    return;
                }

                //黑名单后缀匹配 //未输入时继续处理
                if (Utils.isMatchBlackSuffix(Config.BLACK_SUFFIX_REGX, req_path, false)) {
                    return;
                }

                //获取header列表,包括首行的,每个头行都是一个字符串
                List<String> req_headers = analyzeRequest.getHeaders();
                //获取请求体
                String body = "";;
                byte[] byte_body;
                String req_method = analyzeRequest.getMethod();
                List<String> nobody_method = Arrays.asList("get","head");
                if (nobody_method.contains(req_method.toLowerCase())){
                    byte_body = body.getBytes();
                    stdout.println(String.format("[*] curr req method: [%s] in no body method: %s", req_method, nobody_method));
                }else {
                    //获取body
                    int bodyOffset = analyzeRequest.getBodyOffset();
                    //对消息体进行解析,messageInfo是整个HTTP请求和响应消息体的总和，各种HTTP相关信息的获取都来自于它，HTTP流量的修改都是围绕它进行的。
                    byte[] byte_Request = messageInfo.getRequest();
                    String request = new String(byte_Request); //byte[] to String
                    body = request.substring(bodyOffset);
                    byte_body = body.getBytes();
                }

                //修改头部行的数据
                if (Config.REPLACE_HEAD_LINE) {

                    //存储需要替换的索引号
                    List<Integer> header_index_list = new ArrayList<>();

                    //获取需要修改请求头索引号
                    for (int i = 0; i < req_headers.size(); i++) {
                        String req_header = req_headers.get(i);
                        //查找符合特征的头部行
                        if (Config.REPLACE_HEAD_MATCH.length() == 0 || Utils.isMatchKeywords(Config.REPLACE_HEAD_MATCH, req_header, false)) {
                            header_index_list.add(i);
                        }
                    }

                    //修改符合特征的头部行
                    for (int header_index : header_index_list) {
                        //修改uri信息
                        String old_header_line = req_headers.get(header_index);
                        String new_header_line = old_header_line;

                        //进行精确规则替换
                        if (exact_path != null && exact_path.equals(req_path) && old_header_line.contains(exact_old_string)) {
                            new_header_line = old_header_line.replace(exact_old_string, exact_new_string);
                            req_headers.set(header_index, new_header_line);
                            stdout.println(String.format("[+] exact old header line: [%s] -> exact new header line: [%s]", old_header_line, new_header_line));
                        }else if(rough_replace && old_header_line.contains(rough_old_string)){
                            //进行粗略匹配规则替换
                            new_header_line = old_header_line.replace(rough_old_string, rough_new_string);
                            req_headers.set(header_index, new_header_line);
                            stdout.println(String.format("[+] rough old header line: [%s] -> rough new header line: [%s]", old_header_line, new_header_line));
                        }
                    }
                }

                //修改请求体数据
                if (Config.REPLACE_BODY_LINE) {
                    //进行精确规则替换
                    if (exact_path != null && exact_path.equals(req_path) && body.contains(exact_old_string)) {
                            String new_body = body.replace(exact_old_string, exact_new_string);
                            byte_body = new_body.getBytes();
                            stdout.println(String.format("[+] exact old body length: [%s] -> exact new body length: [%s]",body.length(), new_body.length()));

                    }else if(rough_replace && body.contains(rough_old_string)){
                        //进行粗略匹配规则替换
                        String new_body = body.replace(rough_old_string, rough_new_string);
                        byte_body = new_body.getBytes();
                        stdout.println(String.format("[+] rough old body length: [%s] -> rough new body length: [%s]",body.length(), new_body.length()));
                    }
                }

                //如果修改了header或者修改了body，不能通过updateParameter，使用这个方法。
                byte[] new_Request = helpers.buildHttpMessage(req_headers, byte_body);
                messageInfo.setRequest(new_Request);//设置最终的新请求包
            }
        }
    }

    /**
     * 读取配置文件
     * @param callbacks
     */
    private void ReadConfigYaml(IBurpExtenderCallbacks callbacks) {
        Config.EXTENSION_NAME = YamlReader.getInstance(callbacks).getString(Config.EXTENSION_NAME_STR);
        Config.EXTENSION_VERSION = YamlReader.getInstance(callbacks).getString(Config.EXTENSION_VERSION_STR);

        Config.WHITE_HOST_REGX = YamlReader.getInstance(callbacks).getString(Config.WHITE_HOST_REGX_STR);
        Config.BLACK_HOST_REGX = YamlReader.getInstance(callbacks).getString(Config.BLACK_HOST_REGX_STR);

        Config.WHITE_PATH_REGX = YamlReader.getInstance(callbacks).getString(Config.WHITE_PATH_REGX_STR);
        Config.BLACK_PATH_REGX = YamlReader.getInstance(callbacks).getString(Config.BLACK_PATH_REGX_STR);

        Config.BLACK_SUFFIX_REGX = YamlReader.getInstance(callbacks).getString(Config.BLACK_SUFFIX_REGX_STR);

        Config.REPLACE_HEAD_LINE  = YamlReader.getInstance(callbacks).getBoolean(Config.REPLACE_HEAD_LINE_STR);
        Config.REPLACE_BODY_LINE = YamlReader.getInstance(callbacks).getBoolean(Config.REPLACE_BODY_LINE_STR);

        Config.REPLACE_HEAD_MATCH = YamlReader.getInstance(callbacks).getString(Config.REPLACE_HEAD_MATCH_STR);

        Config.EXACT_REPLACE_RULE = YamlReader.getInstance(callbacks).getString(Config.EXACT_REPLACE_RULE_STR);
        Config.ROUGH_REPLACE_RULE = YamlReader.getInstance(callbacks).getString(Config.ROUGH_REPLACE_RULE_STR);

        Config.RULE_SPLIT_SYMBOL = YamlReader.getInstance(callbacks).getString(Config.RULE_SPLIT_SYMBOL_STR);
    }

    /**
     * 显示读取配置
     */
    private void ShowConfigYaml() {
        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.EXTENSION_NAME_STR, Config.EXTENSION_NAME));
        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.EXTENSION_VERSION_STR, Config.EXTENSION_VERSION))
        ;
        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.WHITE_HOST_REGX_STR, Config.WHITE_HOST_REGX));
        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.BLACK_HOST_REGX_STR, Config.BLACK_HOST_REGX));

        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.WHITE_PATH_REGX_STR, Config.WHITE_PATH_REGX));
        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.BLACK_PATH_REGX_STR, Config.BLACK_PATH_REGX));

        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.BLACK_SUFFIX_REGX_STR, Config.BLACK_SUFFIX_REGX));

        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.REPLACE_HEAD_LINE_STR, Config.REPLACE_HEAD_LINE));
        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.REPLACE_BODY_LINE_STR, Config.REPLACE_BODY_LINE));

        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.REPLACE_HEAD_MATCH_STR, Config.REPLACE_HEAD_MATCH));

        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.EXACT_REPLACE_RULE_STR, Config.EXACT_REPLACE_RULE));
        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.ROUGH_REPLACE_RULE_STR, Config.ROUGH_REPLACE_RULE));

        Utils.showStdoutMsg(1, String.format("[*] INIT %s: %s", Config.RULE_SPLIT_SYMBOL_STR, Config.RULE_SPLIT_SYMBOL));
        Utils.showStdoutMsg(1, "[*] ####################################");
    }

    /**
     * 根据配置文件中的替换规则,填充规则替换的基础变量
     */
    private void SPLIT_RULE() {
        //规则分隔符符号
        String symbol = Config.RULE_SPLIT_SYMBOL;
        //拆分精确规则
        String exact_replace_rule = Config.EXACT_REPLACE_RULE;
        if (exact_replace_rule.contains(symbol)) {
            if (exact_replace_rule.split(symbol).length < 3) {
                stderr.println(String.format("[-] split exact_replace_rule error:[%s]", exact_replace_rule));
            } else {
                exact_path = exact_replace_rule.split(symbol, 3)[0];
                exact_old_string = exact_replace_rule.split(symbol, 3)[1];
                exact_new_string = exact_replace_rule.split(symbol, 3)[2];
                stdout.println(String.format("[*] split exact replace rule normal: [%s]->[%s]->[%s]", exact_path, exact_old_string, exact_new_string));
            }
        }

        //拆分粗略规则
        String rough_replace_rule = Config.ROUGH_REPLACE_RULE;
        if (rough_replace_rule.contains(symbol)) {
            if (rough_replace_rule.split(symbol).length < 2) {
                stderr.println(String.format("[-] split rough replace rule error: [%s]", rough_replace_rule));
            } else {
                rough_old_string = rough_replace_rule.split(symbol, 2)[0];
                rough_new_string = rough_replace_rule.split(symbol, 2)[1];
                rough_replace = true;
                stdout.println(String.format("[*] split rough replace rule normal: [%s]->[%s]", rough_old_string, rough_new_string));
            }
        }
    }
}
