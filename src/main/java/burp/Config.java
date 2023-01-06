package burp;

public class Config {
    public static String EXTENSION_NAME; //扩展名
    public static String EXTENSION_NAME_STR = "EXTENSION_NAME";

    public static String EXTENSION_VERSION; //扩展版本号
    public static String EXTENSION_VERSION_STR = "EXTENSION_VERSION";

    public static String WHITE_HOST_REGX; //白名单HOST匹配正则
    public static String WHITE_HOST_REGX_STR = "WHITE_HOST_REGX";

    public static String BLACK_HOST_REGX; //黑名单HOST匹配正则
    public static String BLACK_HOST_REGX_STR = "BLACK_HOST_REGX";

    public static String WHITE_PATH_REGX; //白名单路径匹配正则
    public static String WHITE_PATH_REGX_STR = "WHITE_PATH_REGX";

    public static String BLACK_PATH_REGX; //黑名单路径匹配正则
    public static String BLACK_PATH_REGX_STR = "BLACK_PATH_REGX";

    public static String BLACK_SUFFIX_REGX; //黑名单扩展匹配正则
    public static String BLACK_SUFFIX_REGX_STR = "BLACK_SUFFIX_REGX";

    //是否替换请求行
    public static Boolean REPLACE_HEAD_LINE;
    public static String REPLACE_HEAD_LINE_STR = "REPLACE_HEAD_LINE";

    //请求行的匹配
    public static String REPLACE_HEAD_MATCH;
    public static String REPLACE_HEAD_MATCH_STR = "REPLACE_HEAD_MATCH";

    //是否替换请求体
    public static Boolean REPLACE_BODY_LINE;
    public static String REPLACE_BODY_LINE_STR = "REPLACE_BODY_LINE";

    //精确替换规则
    public static String EXACT_REPLACE_RULE;
    public static String EXACT_REPLACE_RULE_STR = "EXACT_REPLACE_RULE";

    //粗略替换规则
    public static String ROUGH_REPLACE_RULE;
    public static String ROUGH_REPLACE_RULE_STR = "ROUGH_REPLACE_RULE";

    public static String RULE_SPLIT_SYMBOL;
    public static String RULE_SPLIT_SYMBOL_STR = "RULE_SPLIT_SYMBOL";

}
