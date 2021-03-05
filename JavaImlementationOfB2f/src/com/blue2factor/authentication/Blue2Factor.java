package com.blue2factor.authentication;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import org.json.JSONObject;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;

/*  Blue2Factor b2f = new Blue2Factor();
 *  if (b2f.isAuthenticated(jwt)) {
 *      //show your page
 *  } else {
 *      String url = StringEscapeUtils.escapeHtml(currentUrl);
 *      //"redirect to " + b2f.FAILURE_URL + "?url=" + url;
 *  }
 */

public class Blue2Factor {
    // get these values from your Blue2factor company page at
    // secure.blue2factor.com
    private String myLoginUrl = "https://www.example.com/"; // TODO: CHANGE
    private String myCompanyID = "ABC1234DE56"; // TODO: CHANGE

    // do not change these values
    private final String SECURE_URL = "https://secure.blue2factor.com";
    private final String ENDPOINT = SECURE_URL + "/SAML2/SSO/" + myCompanyID + "/Token";
    public final String FAILURE_URL = SECURE_URL + "/f2Failure";
    private final int SUCCESS = 0;

    /**
     * Checks the token, if it's not successful then gets a new token
     * 
     * @param jwt - java web token as a String
     * @returns whether or not the user was authenticated
     */
    public boolean isAuthenticated(String jwt) {
        boolean success = false;
        if (isTokenValid(jwt)) {
            success = true;
        } else {
            System.out.println("token wasn't valid, will attempt to get a new one");
            success = getNewToken(jwt) != null;
        }
        return success;
    }

    /**
     * Is the current token still valid?
     * 
     * @param jwtString
     * @returns true if it is
     */
    public boolean isTokenValid(String jwtString) {
        boolean validated = false;
        Claims claims = decryptJwt(jwtString);
        if (claims != null) {
            Date now = new Date();
            if (claims.getExpiration().after(now) && now.after(claims.getNotBefore())) {
                if (claims.getId() != null) {
                    if (claims.getIssuer().equals(this.SECURE_URL)) {
                        if (claims.getAudience().equals(this.myLoginUrl)) {
                            validated = true;
                        } else {
                            System.out.println("audience violated: " + claims.getAudience());
                        }
                    } else {
                        System.out.println("issuer violated: " + claims.getIssuer());
                    }
                } else {
                    System.out.println("token not found");
                }
            } else {
                System.out.println("exp or not before violated");
            }
        } else {
            System.out.println("claims was null");
        }
        return validated;
    }

    /**
     * Gets a new token if the user is authenticated and then validates it
     * 
     * @param jwt - java web token as a String
     * @returns the new JWT or null if the user cannot be authenticated
     */
    public String getNewToken(String jwt) {
        String newToken = null;
        try {
            String response = this.getFromServer(this.ENDPOINT, jwt);
            JSONObject jsonObject = new JSONObject(response);
            if (jsonObject.getInt("outcome") == this.SUCCESS) {
                if (isTokenValid(jsonObject.getString("token"))) {
                    newToken = jsonObject.getString("token");
                    // TODO: save the new token so you can use it next time
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return newToken;
    }

    /**
     * Attempts to decrypt a JWT and return the claims
     * 
     * @param jwsString
     * @return Claims
     */
    public Claims decryptJwt(String jwsString) {
        Jws<Claims> jws = null;
        Claims claims = null;
        try {
            PublicKey publicKey = getPublicKey(jwsString);
            // the publicKey can be saved, it only changes monthly
            JwtParserBuilder parseBuilder = Jwts.parserBuilder();
            JwtParser parser = parseBuilder.setSigningKey(publicKey).build();
            jws = parser.parseClaimsJws(jwsString);
            claims = jws.getBody();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return claims;
    }

    /**
     * Gets the public key from the URL in the header of the JWT. The public key can be cached as it
     * does not change often
     * 
     * @param jwsString - JWT
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IOException
     */
    private PublicKey getPublicKey(String jwsString)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String url = decodeUrl(jwsString);
        String rsaPublicKey = getFromServer(url);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
                Base64.getDecoder().decode(rsaPublicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * Gets the url of the Public Key from the JWT header
     * 
     * @param token - JWT
     * @return
     */

    public String decodeUrl(String token) {
        String[] splitToken = token.split("\\.");
        String unsignedToken = splitToken[0] + "." + splitToken[1] + ".";
        JwtParserBuilder parseBuilder = Jwts.parserBuilder();
        JwtParser parser = parseBuilder.build();
        Jwt<?, ?> jwt = parser.parse(unsignedToken);
        Header<?> header = jwt.getHeader();
        String url = (String) header.get(JwsHeader.X509_URL);
        return url;
    }

    /**
     * Make a GET call to the server
     * 
     * @param urlStr
     * @return
     * @throws IOException
     */
    private String getFromServer(String urlStr) throws IOException {
        return getFromServer(urlStr, null);
    }

    /**
     * Make a GET call to the server
     * 
     * @param urlStr
     * @param bearerToken - the expired JWT
     * @return
     * @throws IOException
     */
    private String getFromServer(String urlStr, String bearerToken) throws IOException {
        String response = null;
        URL url = new URL(urlStr);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        if (bearerToken != null) {
            con.setRequestProperty("Authorization", "Bearer " + bearerToken);
        }
        con.setRequestMethod("GET");
        con.setDoOutput(true);
        con.setDoInput(true);
        OutputStream os = con.getOutputStream();
        os.close();
        response = readResponse(con);
        return response;
    }

    /**
     * Read and return the response from the URL
     * 
     * @param con
     * @return the response
     * @throws UnsupportedEncodingException
     * @throws IOException
     */
    private String readResponse(HttpURLConnection con)
            throws UnsupportedEncodingException, IOException {
        StringBuilder response = new StringBuilder();
        if (con.getResponseCode() == 200) {
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(con.getInputStream(), "utf-8"));
            String responseLine = null;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
        } else {
            System.out.println("response code: " + con.getResponseCode());
        }
        return response.toString();
    }
}
