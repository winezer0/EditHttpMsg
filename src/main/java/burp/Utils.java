package burp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utils {
    public static void showStderrMsg(Integer msgLevel,String msg){
            BurpExtender.stderr.println(msg);
    }

    public static void showStdoutMsg(Integer msgLevel, String msg){
            BurpExtender.stdout.println(msg);
    }


    //包含关键字匹配正则
    public static boolean isMatchKeywords(String regx, String str, Boolean NoRegxValue){
        //如果没有正在表达式,的情况下返回指定值 NoRegxValue
        if (regx.trim().length() == 0){
            return NoRegxValue;
        }

        Pattern pat = Pattern.compile("^.*("+regx+").*$",Pattern.CASE_INSENSITIVE);//正则判断
        Matcher mc= pat.matcher(str);//条件匹配
        return mc.find();
    }

    //后缀匹配
    public static boolean isMatchBlackSuffix(String regx, String path, Boolean NoRegxValue){
        //如果没有正在表达式,的情况下返回指定值 NoRegxValue
        if (regx.trim().length() == 0){
            return NoRegxValue;
        }

        String ext = getPathExtension(path);
        //无后缀情况全部放行
        if("".equalsIgnoreCase(ext)){
            return false;
        }else {
            //Pattern pat = Pattern.compile("([\\w]+[\\.]|)("+regx+")",Pattern.CASE_INSENSITIVE);//正则判断
            Pattern pat = Pattern.compile("^("+regx+")$",Pattern.CASE_INSENSITIVE);//正则判断
            Matcher mc= pat.matcher(ext);//条件匹配
            return mc.find();
        }
    }

    //获取请求路径的扩展名
    public static String getPathExtension(String path) {
        String extension="";

        if("/".equals(path)||"".equals(path)){
            return extension;
        }

        try {
            String[] pathContents = path.split("[\\\\/]");
            int pathContentsLength = pathContents.length;
            String lastPart = pathContents[pathContentsLength-1];
            String[] lastPartContents = lastPart.split("\\.");
            if(lastPartContents.length > 1){
                int lastPartContentLength = lastPartContents.length;
                //extension
                extension = lastPartContents[lastPartContentLength -1];
            }
        }catch (Exception exception){
            BurpExtender.stderr.println(String.format("[*] GetPathExtension [%s] Occur Error [%s]", path, exception.getMessage()));
        }
        return extension;
    }

}
