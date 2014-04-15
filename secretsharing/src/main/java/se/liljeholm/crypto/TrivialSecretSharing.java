package se.liljeholm.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * @author torbjorn
 * @since 28 feb 2014 12:07:26
 *
 */
@ThreadSafe
public class TrivialSecretSharing implements SecretSharing {
	private final int participants;

	public TrivialSecretSharing(int participants) {
		this.participants = participants;
	}

	@Override
	public List<Share> share(byte[] secret) {
		KeyGenerator keyGenerator;
		try {
			keyGenerator = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Failed to get KeyGenerator instance", e);
		}
		keyGenerator.init(secret.length * 8);

		List<Share> keys = new ArrayList<Share>(participants);
		
		// Generate keys for participants p up to and including p(n-1)
		byte[] xored = null;
		for (int i = 0; i < participants - 1; i++) {
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] participantKey = secretKey.getEncoded();
			keys.add(new Share(i + 1, participantKey));
			if (xored == null) {
				xored = participantKey;
			} else {
				xored = xor(xored, participantKey);
			}
		}
		
		// Generate key for participant p
		byte[] lastKey = xor(secret, xored);
		keys.add(new Share(keys.size(), lastKey));
		return keys;
	}

	@Override
	public byte[] assemble(List<Share> shares) {
		Share share = shares.get(0);
		byte[] secret = share.getKey();
		for (int i = 1; i < shares.size(); i++) {
			secret = xor(secret, shares.get(i).getKey());
		}
		return secret;
	}
	
	private byte[] xor(byte[] one, byte[] two) {
		if (one.length != two.length) {
			throw new IllegalArgumentException(String.format("Arrays have different length %s != %s", one.length, two.length));
		}
		byte [] xored = new byte[two.length];
		for (int i = 0; i < xored.length; i++) {
			xored[i] = (byte) (one[i] ^ two[i]);
		}
		return xored;
	}
}
