package com.ppcloud.controller;

import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Created by chaogao on 2016/11/29.
 */
@Controller
public class UpFileController extends BaseController {

    //生成上传视频凭证示例代码
    private static final String ACCESS_KEY = "替换为您的Access Key";
    private static final String SECRET_KEY = "替换为您的Secret Key";
    private static final String URL = "http://svc.pptvyun.com/svc/api3/channel";
    private static final String ENCODE = "UTF-8";

    @RequestMapping(value = "/uploadtest/uptoken", method = {RequestMethod.GET})
    public void getUpToken(HttpServletRequest request, HttpServletResponse response) {
        try
        {
            String name = request.getParameter("name");
            String summary = request.getParameter("summary");
            String cover_img = request.getParameter("cover_img");
            String length = request.getParameter("length");
            String ppfeature = request.getParameter("ppfeature");
            if (name == null) name = "";
            if (summary == null) summary = "";
            if (cover_img == null) cover_img = "";
            if (length == null) length = "0";
            if (ppfeature == null) ppfeature = "";
            String result = addVod(name, summary,
                    length, cover_img, ppfeature);
            log.info(result);
            result = result.replace("up_token","upToken");
            result = result.replace("channel_web_id","channelWebId");

            response.setHeader("x-forwarded-for", getIPAddress(request));
            response.setContentType("application/json;charset=utf-8");
            response.getOutputStream().write(result.getBytes("UTF-8"));
            response.getOutputStream().flush();
        } catch (Exception e) {
            log.error("error: " + e.getMessage());
            try {
                response.getOutputStream().write("error".getBytes("UTF-8"));
                response.getOutputStream().flush();
            } catch (Exception e2) {
                log.error("error: " + e2.getMessage());
            }

        }

    }

    public String addVod(String name, String summary,
                         String length, String coverImgUrl, String ppfeature) {
        // 获取token认证字符串
        String auth = getAuthStr(ACCESS_KEY, SECRET_KEY);
        //中文字符处理
        name = encode(name);
        summary = encode(summary);
        String jsonTmpl = "{"
                + "\"ppfeature\": \"%s\","
                + "\"name\": \"%s\","
                + "\"summary\": \"%s\","
                + "\"coverimg\": \"%s\","
                + "\"length\": %s,"
                + "\"type\": 1"
                + "}";
        String body = String.format(jsonTmpl,  ppfeature,
                name, summary, coverImgUrl, length);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", auth);
        headers.put("version", "3.0");

        //注：postJson方法发送POST请求时"Content-Type设置为application/json"
        String result = postJson(URL + "?getuptk=1&reuse=1", body, headers);
        return result;
    }

    //生成接口认证结果示例代码
    private static final String DEFAULT_CHARSET = "UTF-8";
    private static final String ALGORITHM = "HmacSHA1";
    /**
     * 生成接口认证字符串
     */
    public static String getAuthStr(String accessKey, String secretKey) {
        if (accessKey == null || accessKey.equals("") || secretKey == null || secretKey.equals("")) {
            throw new IllegalArgumentException("empty accessKey or secretKey");
        }
        // 1. 生成签名信息：{"rid":"random-string", "deadline":deadline-second}
        String rid = UUID.randomUUID().toString();
        long deadline = System.currentTimeMillis()/1000 + 3600;
        String info = String.format("{\"rid\":\"%s\", \"deadline\":%s}", rid, deadline);
        // 2. 对签名信息做URL安全的Base64编码
        String encodedJsonBase64;
        try {
            encodedJsonBase64 = new String(Base64.encodeBase64(info.getBytes(DEFAULT_CHARSET), false, true));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(String.format("system not support encoding %s", DEFAULT_CHARSET));
        }
        // 3. 使用secret key 对签名信息加密
        byte[] sign;
        try {
            SecretKey sk = new SecretKeySpec(secretKey.getBytes(DEFAULT_CHARSET), ALGORITHM);
            Mac mac = Mac.getInstance(sk.getAlgorithm());
            mac.init(sk);
            sign = mac.doFinal(encodedJsonBase64.getBytes(DEFAULT_CHARSET));
        } catch (Exception e) {
            throw new RuntimeException("sha1 sign error");
        }
        // 4. 加密后的签名信息做URL安全的Base64编码
        String encoded_sign = new String(Base64.encodeBase64(sign, false, true));
        // 5. 生成最终认证字符串
        String accessToken = String.format("%s:%s:%s", accessKey, encoded_sign, encodedJsonBase64);
        return accessToken;
    }

    /**
     * 对中文UTF-8编码
     **/
    private static String encode(String str) {
        try {
            return URLEncoder.encode(str, ENCODE);
        } catch (UnsupportedEncodingException e) {
            return str;
        }
    }

    /**
     * post方式提交json格式数据
     **/
    public static String postJson(String url, String body, Map<String, String> headers) {
        PrintWriter out = null;
        BufferedReader in = null;
        String result = "";
        try {
            URL realUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) realUrl.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json;charset=utf-8");
            for(String key : headers.keySet()){
                conn.setRequestProperty(key, headers.get(key));
            }
            conn.setConnectTimeout(5 * 1000);
            conn.setReadTimeout(10 * 1000);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            out = new PrintWriter(conn.getOutputStream());  //post 参数
            out.print(body);
            out.flush();
            in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String line;
            while ((line = in.readLine()) != null) {
                result += line;
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (out != null)
                    out.close();
                if (in != null)
                    in.close();
            } catch (IOException ex) {//ignore
            }
        }
        return result;
    }
}
