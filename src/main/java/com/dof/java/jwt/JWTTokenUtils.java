package com.dof.java.jwt;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.LogManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTTokenUtils {
	private static final Logger log = LoggerFactory.getLogger(JWTTokenUtils.class);

	private static final String GCP_TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token";
	private static final String PROJECT_ID = "iot-weather-station-project";
	private static final String RSA = "RSA";

	private String serviceAccount = "iotserver-deployer@iot-weather-station-project.iam.gserviceaccount.com";
	private byte[] pkcs8privatekey;

	// LOGGING CONFIG
	static {
		try(InputStream in = JWTTokenUtils.class
				.getClassLoader().getResourceAsStream("logging.properties")){
			LogManager.getLogManager().readConfiguration(in);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}
	
	public JWTTokenUtils(String base64privateKey, String serviceAccount) {
		this.pkcs8privatekey = Base64.getDecoder().decode(base64privateKey);
		if (serviceAccount != null && !serviceAccount.isEmpty())
			this.serviceAccount = serviceAccount;
	}

	@Deprecated
	byte[] readPrivateKey(String key) throws IOException {
		try (InputStream in = getClass().getClassLoader().getResourceAsStream(key);) {
			byte[] buff = new byte[4096];
			int read;
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			while ((read = in.read(buff)) != -1) {
				baos.write(buff, 0, read);
			}
			return baos.toByteArray();
		}
	}

	public String generateSelfSignedJwt() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8privatekey);

		KeyFactory keyFactory = KeyFactory.getInstance(RSA);
		PrivateKey privateKey = keyFactory.generatePrivate(spec);

		Map<String, Object> header = new HashMap<>();
		header.put("type", "JWT");
		header.put("alg", "RS256");

		Map<String, Object> claims = new HashMap<>();
		claims.put("iss", serviceAccount);
		claims.put("scope", "https://www.googleapis.com/auth/cloud-platform");
		claims.put("aud", "https://oauth2.googleapis.com/token");
		claims.put("exp", Long.sum(System.currentTimeMillis() / 1000, 3599));
		claims.put("iat", System.currentTimeMillis() / 1000);

		return Jwts.builder().setClaims(claims).setHeader(header).signWith(SignatureAlgorithm.RS256, privateKey)
				.compact();
	}

	/**
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * 
	 *  create jwt token 
	 *  	head	{ "typ" : "JWT", "alg" : "RS256" }
	 *  	claims	{ "issueat" : "now", "exp" : "1day", "aud" : "project_id" }
	 */
	public String generateSelfSignedJwtNodeMCU() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8privatekey);

		KeyFactory keyFactory = KeyFactory.getInstance(RSA);
		PrivateKey privateKey = keyFactory.generatePrivate(spec);

		Map<String, Object> header = new HashMap<>();
		header.put("typ", "JWT");
		header.put("alg", "RS256");

		return Jwts.builder().setIssuedAt(new Date(System.currentTimeMillis())) // now
				// .setIssuedAt(new Date((System.currentTimeMillis() - 86400000))) // 1 day ago
				.setExpiration(new Date(Long.sum(System.currentTimeMillis(), 86400000))) // 1 day
				// .setExpiration(new Date(Long.sum(System.currentTimeMillis(), 59000))) // 59
				// seconds
				.setAudience(PROJECT_ID).setHeader(header).signWith(SignatureAlgorithm.RS256, privateKey).compact();

	}

	public String gcpIdentityToken() {
		String idToken = null;
		try {
			String signedJwt = generateSelfSignedJwt();
			log.debug("Generated self-signed jwt {}", signedJwt);
			
			URL url = new URL(GCP_TOKEN_URL);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();

			conn.setRequestMethod("POST");
			conn.setRequestProperty("Accept", "*/*");
			conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			conn.setDoOutput(true);

			String payload = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + signedJwt;
			conn.setRequestProperty("Content-Length", String.valueOf(payload.length()));
			byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
			try (OutputStream os = conn.getOutputStream()) {
				os.write(bytes, 0, bytes.length);
			}

			if (conn.getResponseCode() != 200) {
				String message = String.format("%s return error with%nstatus %s%nmessage %s", GCP_TOKEN_URL,
						conn.getResponseCode(), conn.getResponseMessage());
				throw new RuntimeException(message);
			}

			try (BufferedInputStream bis = new BufferedInputStream(conn.getInputStream());
					ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

				byte[] buff = new byte[4096];
				int read = 0;

				while ((read = bis.read(buff)) != -1) {
					baos.write(buff, 0, read);
				}
				String response = new String(baos.toByteArray());
				idToken = response.substring(response.indexOf(":") + 2, response.length() - 2);
				log.info("{}", response);
			}
			conn.disconnect();
			return idToken;
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}

	public static boolean verifyHS256Jwt(String sjwt, String sharedSecret) throws ParseException, JOSEException {
		log.debug("signedJwt: '{}', sharedSecret: '{}'", sjwt, sharedSecret);
		SignedJWT signedJwt = SignedJWT.parse(sjwt);
		JWSVerifier verifier = new MACVerifier(sharedSecret.getBytes(StandardCharsets.UTF_8));
		return signedJwt.verify(verifier);
				//&& signedJwt.getJWTClaimsSet().getAudience().get(0).equalsIgnoreCase(PROJECT_ID);
	}

	public static String generateHS256Jwt(String sharedSecret) {
		Map<String, Object> header = new HashMap<>();
		header.put("typ", "JWT");
		header.put("alg", "RS256");

		return Jwts.builder()
				// .setIssuedAt(new Date(System.currentTimeMillis())) // now
				// .setIssuedAt(new Date((System.currentTimeMillis() - 86400000))) // 1 day ago
				// .setExpiration(new Date(Long.sum(System.currentTimeMillis(), 86400000))) // 1
				// day
				// .setExpiration(new Date(Long.sum(System.currentTimeMillis(), 59000))) // 59
				// seconds
				.setAudience(PROJECT_ID)
				//.setHeader(header)
				.signWith(SignatureAlgorithm.HS256, sharedSecret).compact();
	}

	public static void main(String... args)
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, ParseException, JOSEException {
		// new JWTTokenUtils("iotserver-deployer.der").gcpIdentityToken();
		// new JWTTokenUtils("iotserver-deployer.der",
		// "iotserver-deployer@iot-weather-station-project.iam.gserviceaccount.com").gcpIdentityToken();
		// new JWTTokenUtils("iot-ws-sa.der",
		// "iot-ws-sa@iot-weather-station-project.iam.gserviceaccount.com").gcpIdentityToken();
		// System.out.println(new JWTTokenUtils("iotws-publisher.der",
		// "").generateSelfSignedJwtNodeMCU());

		// System.out.println(verifyJwtHS256("eyJ0eXAiOiAiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJhdWQiOiJpb3Qtd2VhdGhlci1zdGF0aW9uLXByb2plY3QiLCJpYXQiOjE2NjE5ODMyMDAsImV4cCI6MTY2NDQ4ODgwMH0.CqpWsz2qEyM59ohB-4tL4WIVNLDXsQGL-FsI9LyR4Ow"));

		// System.out.println(JWTTokenUtils.jwtHS256Creator(null));
		// System.out.println(new JWTTokenUtils("iotws-publisher.der",
		// null).generateSelfSignedJwtNodeMCU());

		if (args == null || args.length == 0) {
			log.info("No argument passed.");
			printHelp();
		} else if (args.length >= 2) {
			if (args.length == 2 && args[0].equals("-hs256")) {
				log.info(generateHS256Jwt(args[1]));
			} else if (args[0].equals("-hs256verify") && args.length == 3) {
				log.info(String.format("verified: %b", verifyHS256Jwt(args[1], args[2])));
			}else if(args.length == 3 && args[0].equals("-rs256")) {
				String jwt = new com.dof.java.jwt.JWTTokenUtils(args[1], args[2]).generateSelfSignedJwt();
				log.info("SelfSigned RS256 Jwt: {}", jwt);
			}else if(args.length == 3 && args[0].equals("-gcpIdToken")) {
				String jwt = new com.dof.java.jwt.JWTTokenUtils(args[1], args[2]).gcpIdentityToken();
				log.info("Gcp Identity Token: {}", jwt);
			}
			
			else {
				printHelp();
			}
		} else {
			printHelp();
		}

	}

	private static void printHelp() {
		StringBuilder sb = new StringBuilder("USAGE\n");
		sb.append(" -hs256\t\t<shared-secret>\t\tgenerate hs256 jwt\n");
		sb.append(" -hs256verify\t<jwt> <shared-secret>\tverify hs256 jwt\n");
		sb.append(" -rs256\t\t<base64-private-key> <service-account>\n");
		sb.append(" -gcpIdToken\t<base64-private-key> <service-account>");
		System.out.println(sb.toString());
	}

}
