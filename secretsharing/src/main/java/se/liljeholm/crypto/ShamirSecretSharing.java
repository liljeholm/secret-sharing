package se.liljeholm.crypto;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * @author torbjorn
 * @since 28 feb 2014 12:07:26
 *
 */
public class ShamirSecretSharing implements SecretSharing {
	private static final int GALOIS_FIELD = 256;
	private int threshold; // k
	private int participants; // n
	private SecureRandom secureRandom;
	
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
			int[] coefficients = new int[threshold - 1];
			for (int coeffIndex = 0; coeffIndex < threshold - 1; coeffIndex++) {
				coefficients[coeffIndex] = secureRandom.nextInt(255) + 1;
			}
			
			// Calculate shares
			for (Share share : shares) {
				int x = share.getShare();
				byte[] key = share.getKey();
				
				// Calculate f(x) = 1234 + 166x + 94x^2... in GF 256
				int fx = toUnsigned(secret[byteIndex]);
				for (int coeffIndex = 0; coeffIndex < coefficients.length; coeffIndex++) {
					fx = (int) ((fx + coefficients[coeffIndex] * (Math.pow(x, coeffIndex + 1) % GALOIS_FIELD) % GALOIS_FIELD) % GALOIS_FIELD);
				}
				key[byteIndex] = (byte) fx; 
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
			
			int result = 0;
			for (int i = 0; i < shares.size(); i++) {
				int y = shares.get(i).getKey()[byteIndex];
				int l = 1;
				for (int j = 0; j < i; j++) {
					if (i != j) {
						l *= shares.get(j).getShare() / (shares.get(j).getShare() - shares.get(i).getShare());
					}
				}
				result += (y * l) % GALOIS_FIELD; 
			}

			if (result > 127) {
				key[byteIndex] = (byte) (256 - result);
			} else {
				key[byteIndex] = (byte) result;
			}
		}
		return key;
	}
}
