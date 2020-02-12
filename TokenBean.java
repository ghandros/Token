

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.*;

import com.sap.aii.af.service.idmap.MessageIDMapper;
import com.sap.aii.af.lib.mp.module.Module;
import com.sap.aii.af.lib.mp.module.ModuleContext;
import com.sap.aii.af.lib.mp.module.ModuleData;
import com.sap.aii.af.lib.mp.module.ModuleException;
import com.sap.engine.interfaces.messaging.api.*;
import com.sap.engine.interfaces.messaging.api.auditlog.AuditAccess;
import com.sap.engine.interfaces.messaging.api.auditlog.AuditLogStatus;
import com.sap.engine.interfaces.messaging.api.exception.InvalidParamException;
import com.sap.tc.logging.Location;

import com.sap.security.core.server.https.Utils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.w3c.dom.Document;

import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

public class TokenBean implements Module
{
    private static final String LOG_PREFIX = TokenBean.class.getSimpleName() + ": ";
    private static final Location TRACE = Location.getLocation(TokenBean.class.getName());
    private static final String CLASS_NAME = TokenBean.class.getSimpleName();

    private AuditAccess audit;
    private MessageKey messageKey;
    private Message message;
    private SimpleDateFormat sdf;

    private HashMap<String,String> customParams = new HashMap<>();
    private boolean store;
    private int storePeriod;
    private String url;
    private String method;
    private String loginField;
    private String loginValue;
    private String passField;
    private String passValue;
    private String basicUser;
    private String basicPass;
    private String dcNS;
    private String dcKey;
    private String respFormat;
    private String respTokenPath;
    private String respExpDatePath;
    private String respDateFormat;
    private boolean respLog;

    private String token;
    private String expDate;

    public ModuleData process(ModuleContext mc, ModuleData md) throws ModuleException
    {
        try
        {
            MessageIDMapper mim = MessageIDMapper.getInstance();
            message = (Message) md.getPrincipalData();
            // initialize logging
            messageKey = message.getMessageKey();
            audit = PublicAPIAccessFactory.getPublicAPIAccess().getAuditAccess();
            // log module entrance point
            log("Module called");
            // initialize parameters
            initParams(mc);
            log("Module parameters initialized");
            // if storage is configured, check if there is a valid token
            if(store)
            {
                log("Store mode configured");
                // remove expired tokens
                mim.removeExpiredIDMaps();
                // get token key
                String tokenKey = String.join(":", CLASS_NAME, url, loginValue);
                // get stored token
                token = mim.getMappedId(tokenKey);
                // if token is expired, get the new one
                if(token == null)
                {
                    log("No valid token found");
                    // get new token
                    getNewToken();
                    // if expiration date is got from response, use it, otherwise use store period
                    long expTimestamp;
                    if(expDate == null || expDate.isEmpty())
                    {
                        log("No expiration date got from response, using store period");
                        expTimestamp = new Date().getTime() + storePeriod * 60000;
                    }
                    else
                    {
                        expTimestamp =  sdf.parse(expDate).getTime();
                        log("Expiration date got from response");
                    }
                    // save new token
                    mim.createIDMap(tokenKey, token, expTimestamp);
                    log("New token successfully stored");
                    log("Expiration timestamp: " + sdf.format(new Date(expTimestamp)));
                }
                else
                    log("Stored token is valid");
            }
            // otherwise simply get the new token
            else
                getNewToken();
            // write token to Dynamic Configuration
            MessagePropertyKey mpk = new MessagePropertyKey(dcKey, dcNS);
            message.setMessageProperty(mpk, token);
            log("Token " + token + " successfully written to DC");
            log("Module finished");
            return md;
        }
        catch (Exception e)
        {
            logError(e.getMessage());
            throw new ModuleException(e);
        }
    }

    private void getNewToken() throws Exception
    {
        String account = loginField + "=" + loginValue + "&" + passField + "=" + passValue;
        String body = account;
        // add account parameters to URL
        if(method.equals("GET"))
            url += url.contains("?") ? "&" : "?" + account;
        body += processHTTPParameters();
        log("Requesting new token from URL " + url);
        // initializing connection
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod(method);
        if(method.equals("POST"))
        {
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        }
        // setting basic authentication if required
        if(basicUser != null && basicPass != null)
            Utils.setBasicAuthenticationHeader(conn, basicUser, basicPass);
        // adding custom headers to request
        addCustomHeaders(conn);
        if(method.equals("POST"))
        {
            // sending the request
            OutputStream os = conn.getOutputStream();
            os.write(body.getBytes());
            os.flush();
            os.close();
        }
        int respCode = conn.getResponseCode();
        if(respCode != 200)
            throw new Exception("Token request failed with code " + respCode +
                    ",reason: " + conn.getResponseMessage());
        log("HTTP call successfully completed");
        // processing the response
        InputStream is = conn.getInputStream();
        if(respFormat.equals("JSON"))
            processJSONResponse(is);
        else
            processXMLResponse(is);
        if(token == null || token.isEmpty())
            throw new Exception("No token got from response");
        log("HTTP response successfully parsed");
    }

    private void processJSONResponse(InputStream is) throws Exception
    {
        JSONParser parser = new JSONParser();
        Object obj = parser.parse(new InputStreamReader(is));
        // log the response
        if(respLog)
            log(((JSONObject)obj).toJSONString());
        // get token by field name
        Map<String, String> jsonMap = (HashMap<String, String>) obj;
        token = jsonMap.get(respTokenPath);
        // get expiration date by field name if configured
        if(respExpDatePath != null)
        {
            expDate = jsonMap.get(respExpDatePath);
            if(expDate == null || expDate.isEmpty())
                throw new Exception("No expiration date got from response");
        }
    }

    private void processXMLResponse(InputStream is) throws Exception
    {
        Document response = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
        // log the response
        if(respLog)
        {
            Transformer tfr = TransformerFactory.newInstance().newTransformer();
            tfr.setOutputProperty(OutputKeys.INDENT, "yes");
            StringWriter sw = new StringWriter();
            tfr.transform(new DOMSource(response), new StreamResult(sw));
            log(sw.toString());
        }
        // get token by xpath
        XPath xpath = XPathFactory.newInstance().newXPath();
        XPathExpression exprToken = xpath.compile(respTokenPath);
        token = exprToken.evaluate(response);
        // get expiration date by xpath if configured
        if(respExpDatePath != null)
        {
            XPathExpression exprDate = xpath.compile(respExpDatePath);
            expDate = exprDate.evaluate(response);
            if(expDate == null || expDate.isEmpty())
                throw new Exception("No expiration date got from response");
        }
    }

    private String processHTTPParameters() throws Exception
    {
        StringBuilder urlSb = new StringBuilder();
        StringBuilder bodySb = new StringBuilder();
        HashMap<Integer,String> names = new HashMap<>();
        HashMap<Integer,String> types = new HashMap<>();
        HashMap<Integer,String> values = new HashMap<>();
        HashMap<Integer,String> paths = new HashMap<>();
        HashMap<Integer,String> pathURI = new HashMap<>();
        HashMap<Integer,String> pathPrefix = new HashMap<>();
        // parsing http parameters
        for(String s : customParams.keySet())
            if(s.contains("req.param") && s.contains(".name"))
            {
                int index = Integer.valueOf(s.substring(9, s.lastIndexOf(".")));
                names.put(index, customParams.get(s));
            }
            else if(s.contains("req.param") && s.contains(".type"))
            {
                int index = Integer.valueOf(s.substring(9, s.lastIndexOf(".")));
                types.put(index, customParams.get(s));
            }
            else if(s.contains("req.param") && s.contains(".value"))
            {
                int index = Integer.valueOf(s.substring(9, s.lastIndexOf(".")));
                values.put(index, customParams.get(s));
            }
            else if(s.contains("req.param") && s.contains(".path"))
            {
                int index = Integer.valueOf(s.substring(9, s.lastIndexOf(".")));
                paths.put(index, customParams.get(s));
            }
            else if(s.contains("req.param") && s.contains(".uri"))
            {
                int index = Integer.valueOf(s.substring(9, s.lastIndexOf(".")));
                pathURI.put(index, customParams.get(s));
            }
            else if(s.contains("req.param") && s.contains(".prefix"))
            {
                int index = Integer.valueOf(s.substring(9, s.lastIndexOf(".")));
                pathPrefix.put(index, customParams.get(s));
            }
        Document xml = null;
        XPath xpath = null;
        if(!paths.isEmpty())
        {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            InputStream is = message.getMainPayload().getInputStream();
            xml = dbf.newDocumentBuilder().parse(is);
            xpath = XPathFactory.newInstance().newXPath();
        }
        for(int i : names.keySet())
        {
            String value = values.get(i);
            if(value == null)
            {
                value = "";
                String path = paths.get(i);
                if(path != null)
                {
                    String uri = pathURI.get(i);
                    String prefix = pathPrefix.get(i);
                    if(uri != null && prefix != null && !uri.isEmpty() && !prefix.isEmpty())
                        xpath.setNamespaceContext(new NamespaceContext()
                        {
                            @Override
                            public String getNamespaceURI(String s)
                            {
                                return s.equals(prefix) ? uri : null;
                            }

                            @Override
                            public String getPrefix(String s)
                            {
                                return null;
                            }

                            @Override
                            public Iterator getPrefixes(String s)
                            {
                                return null;
                            }
                        });
                    String res = xpath.compile(path).evaluate(xml);
                    if(res != null && !res.isEmpty())
                        value = res;
                }
            }
            String type = types.get(i);
            if(type != null && type.equalsIgnoreCase("body"))
                bodySb.append("&").append(URLEncoder.encode(names.get(i), "UTF-8")).append("=")
                        .append(URLEncoder.encode(value, "UTF-8"));
            else
                urlSb.append("&").append(URLEncoder.encode(names.get(i), "UTF-8")).append("=")
                        .append(URLEncoder.encode(value, "UTF-8"));
        }
        url += urlSb.toString();
        return bodySb.toString();
    }

    private void addCustomHeaders(HttpURLConnection conn)
    {
        HashMap<Integer,String> names = new HashMap<>();
        HashMap<Integer,String> values = new HashMap<>();
        // parsing header module parameters
        for(String s : customParams.keySet())
            if(s.contains("req.header") && s.contains(".name"))
            {
                int index = Integer.valueOf(s.substring(10, s.lastIndexOf(".")));
                names.put(index, customParams.get(s));
            }
            else if(s.contains("req.header") && s.contains(".value"))
            {
                int index = Integer.valueOf(s.substring(10, s.lastIndexOf(".")));
                values.put(index, customParams.get(s));
            }
        // adding headers to request
        for(int i : names.keySet())
            conn.addRequestProperty(names.get(i), values.get(i));
    }

    private void initParams(ModuleContext mc) throws Exception
    {
        Enumeration en = mc.getContextDataKeys();
        // parsing module parameters
        while (en.hasMoreElements())
        {
            String paramName = (String) en.nextElement();
            String paramValue = mc.getContextData(paramName);
            switch (paramName)
            {
                case "store": store = "yes".equalsIgnoreCase(paramValue); break;
                case "store.period": storePeriod = Integer.valueOf(paramValue); break;
                case "req.url": url = paramValue; break;
                case "req.http.method": method =
                            "post".equalsIgnoreCase(paramValue) ? "POST" : "GET"; break;
                case "req.login.field": loginField = URLEncoder.encode(paramValue, "UTF-8"); break;
                case "req.login.value": loginValue = URLEncoder.encode(paramValue, "UTF-8"); break;
                case "req.pass.field": passField = URLEncoder.encode(paramValue, "UTF-8"); break;
                case "req.pass.value": passValue = URLEncoder.encode(paramValue, "UTF-8"); break;
                case "req.auth.basic.user": basicUser = paramValue; break;
                case "req.auth.basic.pass": basicPass = paramValue; break;
                case "dc.ns": dcNS = paramValue; break;
                case "dc.key": dcKey = paramValue; break;
                case "resp.format": respFormat = "xml".equalsIgnoreCase(paramValue) ? "XML" : "JSON"; break;
                case "resp.token.path": respTokenPath = paramValue; break;
                case "resp.expdate.path": respExpDatePath = paramValue; break;
                case "resp.date.format": respDateFormat = paramValue; break;
                case "resp.log": respLog = "yes".equalsIgnoreCase(paramValue); break;
                default: customParams.put(paramName, paramValue);
            }
        }
        // check mandatory parameters and initialize default values
        if (url == null)
            throw new InvalidParamException("Mandatory parameter req.url is missing");
        if (method == null)
            method = "GET";
        if (loginField == null)
            loginField = "login";
        if (loginValue == null)
            throw new InvalidParamException("Mandatory parameter req.login.value is missing");
        if (passField == null)
            passField = "password";
        if (passValue == null)
            throw new InvalidParamException("Mandatory parameter req.pass.value is missing");
        if (dcNS == null)
            dcNS = "http://sap.com/xi/XI/System/REST";
        if (dcKey == null)
            dcKey = "id";
        if (respFormat == null)
            respFormat = "JSON";
        if (respTokenPath == null)
            throw new InvalidParamException("Mandatory parameter resp.token.path is missing");
        if (store && storePeriod <= 0 && respExpDatePath == null)
            throw new InvalidParamException("Positive store.period or resp.expdate.path " +
                    "should be specified");
        if (respDateFormat == null)
            respDateFormat = "yyyy-MM-dd'T'HH:mm:ssXXX";
        sdf = new SimpleDateFormat(respDateFormat);
    }

    private void log(String text)
    {
        audit.addAuditLogEntry(messageKey, AuditLogStatus.SUCCESS, LOG_PREFIX + text);
        TRACE.infoT(LOG_PREFIX + text);
    }

    private void logError(String text)
    {
        audit.addAuditLogEntry(messageKey, AuditLogStatus.ERROR, LOG_PREFIX + text);
        TRACE.errorT(LOG_PREFIX + text);
    }
}
