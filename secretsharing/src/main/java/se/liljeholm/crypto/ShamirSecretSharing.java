package se.liljeholm.crypto;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import javax.annotation.concurrent.ThreadSafe;

/**
 * @author torbjorn
 * @since 28 feb 2014 12:07:26
 *
 */
@ThreadSafe
public class ShamirSecretSharing implements SecretSharing {
	private static final Logger LOG = Logger.getLogger(ShamirSecretSharing.class.getSimpleName());
	private static final int GALOIS_FIELD = 256;
	private final int threshold; // k
	private final int participants; // n
	private final SecureRandom secureRandom;
	
	public ShamirSecretSharing(int threshold, int participants) {
		this.threshold = threshold;
		this.participants = participants;
		this.secureRandom = new SecureRandom();
	}

	@Override
	public List<Share> share(byte[] secret) {
		List<Share> shares = new ArrayList<Share>();
		
		// Create shares
		for (int participant = 0; participant < participants; participant++) {
			shares.add(new Share(participant + 1, new byte[secret.length]));
		}

		// For each byte we calculate all shares at the same time
		for (int byteIndex = 0; byteIndex < secret.length; byteIndex++) {

			// Create threshold - 1 random coefficients in GF 256
//			int[] coefficients = new int[] {1, 2};
			int[] coefficients = new int[threshold - 1];
			for (int coeffIndex = 0; coeffIndex < threshold - 1; coeffIndex++) {
				coefficients[coeffIndex] = secureRandom.nextInt(255) + 1;
			}
			
			// Calculate one byte for each share
			for (Share share : shares) {
				int x = share.getShare();
				
				// Calculate f(x) = 1234 + 166x + 94x^2... in GF 256
				int fx = toUnsigned(secret[byteIndex]);
				StringBuilder sb = new StringBuilder(String.valueOf(fx));
				for (int coeffIndex = 0; coeffIndex < coefficients.length; coeffIndex++) {
					fx = (int) ((fx + coefficients[coeffIndex] * (Math.pow(x, coeffIndex + 1) % GALOIS_FIELD) % GALOIS_FIELD) % GALOIS_FIELD);
					sb.append(" + ").append(coefficients[coeffIndex]).append("x");
					sb.append(x).append("^").append(coeffIndex + 1);
				}
				// Update share
				share.getKey()[byteIndex] = (byte) fx;
				sb.append(" = ").append(fx);
				LOG.info(sb.toString());
			}
		}
		return shares;
	}
	
	private int toUnsigned(byte b) {
		return b < 0 ? b + GALOIS_FIELD : b;
	}
	
	@Override
	public byte[] assemble(List<Share> shares) {
		if (shares.size() < threshold) {
			throw new IllegalArgumentException(String.format("Threshold not met. Expecting %s, got %s", threshold, shares.size()));
		}
		byte[] key = new byte[shares.get(0).getKey().length];
		for (int byteIndex = 0; byteIndex < key.length; byteIndex++) {
			double result = 0;
			for (int i = 0; i < shares.size(); i++) {
				double y = shares.get(i).getKey()[byteIndex];
				double l = 1;
				for (int j = 0; j < shares.size(); j++) {
					if (i != j) {
						double xj = shares.get(j).getShare();
						double xi = shares.get(i).getShare();
						l *= xj / (xj - xi);
					}
				}
				result += (y * l);
			}
			key[byteIndex] = (byte) result;
		}
		return key;
	}
}
