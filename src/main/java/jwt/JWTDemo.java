package jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JWTDemo {

    private static final Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", Pattern.DOTALL);

    private static String createHS256(String issuer, String audience, int expMins) {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        Date expDate = new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(expMins));
        return JWT.create()
                .withExpiresAt(expDate)
                .withAudience(audience)
                .withIssuer(issuer)
                .sign(algorithm);
    }

    private static String createRS256(String issuer, String audience, int expMins) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKey publicKey = loadPEMPublicKey("keys/public.pem");
//        RSAPrivateKey privateKey = loadDERPrivateKey("keys/private.der");
        RSAPrivateKey privateKey = loadPEMPrivateKey("keys/private.pem");
        Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
        Date expDate = new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(expMins));
        return JWT.create()
                .withExpiresAt(expDate)
                .withAudience(audience)
                .withIssuer(issuer)
                .sign(algorithm);
    }

    private static DecodedJWT verifyRS256(String token, String issuer) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        RSAPublicKey publicKey = loadPEMPublicKey("keys/public.pem");
        Algorithm algorithm = Algorithm.RSA256(publicKey, null);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build(); //Reusable verifier instance
        return verifier.verify(token);
    }

    private static RSAPublicKey loadPEMPublicKey(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (InputStream is = JWTDemo.class.getClassLoader().getResourceAsStream(path)) {
            if (is != null) {
                try (InputStreamReader isr = new InputStreamReader(is);
                     PemReader pemReader = new PemReader(isr)) {

                    PemObject pemObject = pemReader.readPemObject();
                    byte[] keyBytes = pemObject.getContent();

                    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    return (RSAPublicKey) kf.generatePublic(spec);
                }
            } else {
                throw new RuntimeException("No public key found at " + path);
            }
        }
    }

    private static RSAPrivateKey loadPEMPrivateKey(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (InputStream is = JWTDemo.class.getClassLoader().getResourceAsStream(path)) {
            String pemData = IOUtils.toString(IOUtils.toByteArray(is), "UTF-8");
            Matcher m = PEM_DATA.matcher(pemData.trim());
            if (!m.matches()) {
                throw new IllegalArgumentException("String is not PEM encoded data");
            }
            String type = m.group(1);
            if (type.equals("RSA PRIVATE KEY")) {
                String rawKey = m.group(2);
                final byte[] keyBytes = Base64.decode(rawKey.getBytes(StandardCharsets.UTF_8));
                ASN1Sequence sequence = ASN1Sequence.getInstance(keyBytes);
                if (sequence.size() != 9) {
                    throw new IllegalArgumentException("Invalid RSA Private Key ASN1 sequence.");
                }
                org.bouncycastle.asn1.pkcs.RSAPrivateKey privateKey =
                        org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(sequence);
                RSAPrivateCrtKeySpec privSpec = new RSAPrivateCrtKeySpec(
                        privateKey.getModulus(),
                        privateKey.getPublicExponent(),
                        privateKey.getPrivateExponent(),
                        privateKey.getPrime1(),
                        privateKey.getPrime2(),
                        privateKey.getExponent1(),
                        privateKey.getExponent2(),
                        privateKey.getCoefficient());
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return (RSAPrivateKey) kf.generatePrivate(privSpec);
            } else {
                throw new RuntimeException(String.format("%s is not a PEM format key", path));
            }
        }
    }

    private static RSAPrivateKey loadDERPrivateKey(String path)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (InputStream is = JWTDemo.class.getClassLoader().getResourceAsStream(path)) {
            byte[] keyBytes = IOUtils.toByteArray(is);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) kf.generatePrivate(spec);
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        String issuer = "test_issuer";
        String audience = "test_audience";

        String token;

        token = createHS256(issuer, audience, 5);
        System.out.println("HS256 JWT token: " + token);

        token = createRS256(issuer, audience, 5);
        System.out.println("RS256 JWT token: " + token);

        DecodedJWT decodedJWT = verifyRS256(token, issuer);
        System.out.printf("Verified JWT issuer: %s,  expired at %s",
                decodedJWT.getIssuer() , decodedJWT.getExpiresAt());
    }
}
