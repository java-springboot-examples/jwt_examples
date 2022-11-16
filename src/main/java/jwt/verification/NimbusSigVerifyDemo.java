package jwt.verification;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.JWKSetCache;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.concurrent.TimeUnit;

public class NimbusSigVerifyDemo {

    public static void main(String[] args) throws MalformedURLException, ParseException {
        if (args.length > 0) {
            String accessToken = args[0];
            JWT jwt = JWTParser.parse(accessToken);

            System.out.println(jwt.getHeader());

            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

            URL jwksUrl = new URL("https://login.microsoftonline.com/common/discovery/keys");
            long cacheLifespan = 500;
            long refreshTime = 400;
            JWKSetCache jwkSetCache = new DefaultJWKSetCache(cacheLifespan, refreshTime, TimeUnit.MINUTES);

            JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(jwksUrl, null, jwkSetCache);

            JWSAlgorithm expectedJWSAlg = (JWSAlgorithm) jwt.getHeader().getAlgorithm();
            JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
            jwtProcessor.setJWSKeySelector(keySelector);

            try {
                for (int i=0;i<3;i++) {
                    JWTClaimsSet claimsSet = jwtProcessor.process(jwt, null);
                    System.out.println(claimsSet.toJSONObject());
                }
            } catch (BadJOSEException | JOSEException e) {
                e.printStackTrace();
            }
        } else {
            System.err.println("Missing access token as the first argument");
        }
    }
}
