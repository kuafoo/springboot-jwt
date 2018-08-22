package com.fanduo.jwt.common;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Simple JasonWebToken
 * https://tools.ietf.org/html/rfc7519
 */
@Slf4j
public class JsonWebToken {
    private static ObjectMapper objectMapper = null;
    private String algorithm;
    private Map<String, String> header;
    private Map<String, String> payload;
    private String signature;

    private JsonWebToken()
    {

    }

    public static final String ALGORITHM_HMACMD5 = "HmacMD5";
    public static final String ALGORITHM_HMACSHA1= "HmacSHA1";
    public static final String ALGORITHM_HMACSHA256 = "HmacSHA256";
    public static final String ALGORITHM_HMACSHA512= "HmacSHA512";

    private JsonWebToken init()
    {
        return init(ALGORITHM_HMACSHA256);
    }

    private JsonWebToken init(String algorithm)
    {
        header = new HashMap<>();

        this.algorithm = algorithm;
        header.put("alg",algorithm);
        header.put("typ","JWT");

        payload = new HashMap<>();

        signature = "";

        return this;
    }

    public JsonWebToken setSubject(String sub)
    {
        addPayload("sub",sub);
        return this;
    }

    public JsonWebToken setIssuer(String iss)
    {
        addPayload("iss",iss);
        return this;
    }

    public JsonWebToken setAudience(String aud)
    {
        addPayload("aud",aud);
        return this;
    }

    public JsonWebToken setExpirationTime(String exp)
    {
        addPayload("exp",exp);
        return this;
    }

    public JsonWebToken setNotBefore(String nbf)
    {
        addPayload("nbf",nbf);
        return this;
    }

    public JsonWebToken setIssuedAt(String iat)
    {
        addPayload("iat",iat);
        return this;
    }

    public JsonWebToken setJwtId(String jti)
    {
        addPayload("jti",jti);
        return this;
    }

    public String getSubject(String sub)
    {
        return getPayload("sub");
    }

    public String getIssuer(String iss)
    {
        return getPayload("iss");
    }

    public String getAudience(String aud)
    {
        return getPayload("aud");
    }

    public String getExpirationTime(String exp)
    {
        return getPayload("exp");
    }

    public String getNotBefore(String nbf)
    {
        return getPayload("nbf");
    }

    public String getIssuedAt(String iat)
    {
        return getPayload("iat");
    }

    public String getJwtId(String jti)
    {
        return getPayload("jti");
    }

    public JsonWebToken addPayload(String key, String value)
    {
        payload.put(key, value);
        return this;
    }

    public String getPayload(String key)
    {
        if(payload.containsKey(key)) {
            return payload.get(key);
        }
        else{
            return "";
        }
    }

    public String compact(String secret)
    {
        ObjectMapper objectMapper = new ObjectMapper();

        String headerJson;
        String payloadJson;

        try
        {
            headerJson = objectMapper.writeValueAsString(header);
            payloadJson = objectMapper.writeValueAsString(payload);
        }
        catch (JsonProcessingException e)
        {
            return "";
        }

        StringBuilder message = new StringBuilder();
        message.append(Base64Utils.encodeToString(headerJson.getBytes()));
        message.append(".");
        message.append(Base64Utils.encodeToString(payloadJson.getBytes()));
        String sign = sign(algorithm, message.toString(), secret);
        return message.append(".").append(sign).toString();
    }

    private static ObjectMapper getObjectMapper()
    {
        if(objectMapper == null)
        {
            objectMapper = new ObjectMapper();
        }
        return objectMapper;
    }

    public static JsonWebToken build()
    {
        return new JsonWebToken().init();
    }

    public static JsonWebToken build(String algorithm)
    {
        return new JsonWebToken().init(algorithm);
    }

    public static JsonWebToken parse(String token, String secret)
    {
        if(verify(token, secret))
        {
            return parse(token);
        }
        return null;
    }

    private static JsonWebToken parse(String token)
    {
        JsonWebToken jwt = new JsonWebToken();

        String[] tokens = StringUtils.split(token, ".");

        //convert token to header
        String header = new String(Base64Utils.decodeFromString(tokens[0]));
        //convert order to object
        try
        {
            jwt.header = getObjectMapper().readValue(header, new TypeReference<HashMap<String, String>>(){});
        }
        catch (Exception e)
        {
            log.error("parse header >>> {}",e);
            return null;
        }


        String payload = new String(Base64Utils.decodeFromString(tokens[1]));
        try
        {
            jwt.payload = getObjectMapper().readValue(payload, new TypeReference<HashMap<String, String>>(){});
        }
        catch (Exception e)
        {
            log.error("parse payload >>> {}",e);
            return null;
        }

        jwt.signature = tokens[2];

        return jwt;
    }

    public static boolean verify(String token, String secret, String algorithm)
    {
        if(StringUtils.isEmpty(token)) return false;

        String[] tokens = StringUtils.split(token, ".");
        if(tokens.length != 3)
        {
            return false;
        }

        String message = tokens[0] + "." + tokens[1];

        if(tokens[2].equals(sign(algorithm, message, secret)))
        {
            return true;
        }
        return false;
    }

    public static boolean verify(String token, String secret)
    {
        if(StringUtils.isEmpty(token)) return false;

        String[] tokens = token.split(".");
        if(tokens.length != 3)
        {
            return false;
        }

        try
        {
            //convert token to header
            String header = new String(Base64Utils.decodeFromString(tokens[0]));
            //convert order to object
            HashMap<String,String> headerObject = getObjectMapper().readValue(header, new TypeReference<HashMap<String,String>>(){});
            //get algorithm method
            String algorithm = headerObject.get("alg");
            return verify(token, secret, algorithm);
        }
        catch(Exception e)
        {
            log.error(e.getMessage());
            return false;
        }
    }


    /**
     * https://stackoverflow.com/questions/7124735/hmac-sha256-algorithm-for-signature-calculation
     * @param algorithm
     * @param message
     * @param secret
     * @return
     */
    private static String sign(String algorithm, String message, String secret)
    {
        try  {
            // 1. Get an algorithm instance.
            Mac hmac = Mac.getInstance(algorithm);

            // 2. Create secret key.
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes("UTF-8"), algorithm);

            // 3. Assign secret key algorithm.
            hmac.init(secret_key);

            // 4. Generate Base64 encoded cipher string.
            String hash = Base64Utils.encodeToString(hmac.doFinal(message.getBytes("UTF-8")));

            // You can use any other encoding format to get hash text in that encoding.
            return hash;
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
        } catch (InvalidKeyException e) {
            log.error(e.getMessage());
        } catch (UnsupportedEncodingException e) {
            log.error(e.getMessage());
        }
        return "";
    }
}
