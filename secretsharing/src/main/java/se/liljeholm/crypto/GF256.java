package se.liljeholm.crypto;


/**
 * @author torbjorn
 * @since 21 mar 2014 11:05:14
 *
 */
public class GF256 {
	private static final int GALOIS_FIELD = 256;

	public static int add(int a, int b) {
		validate(a);
		validate(b);
		
		return a ^ b;
	}
	
	private static void validate(int a) {
		if (!(a >= 0 && a < GALOIS_FIELD)) {
			throw new IllegalArgumentException(String.format("Value %s is out of bounds."
					+ " Must be between 0 (incl.) and %s (excl.).", a, GALOIS_FIELD));
		}
	}
}
