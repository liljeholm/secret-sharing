package se.liljeholm.crypto;

import java.util.Arrays;

/**
 * @author torbjorn
 * @since 20 mar 2014 12:59:44
 * 
 */
public class Share {
	private final int share;
	private final byte[] key;

	public Share(int share, byte[] key) {
		super();
		this.share = share;
		this.key = Arrays.copyOf(key, key.length);
	}

	public int getShare() {
		return share;
	}

	public byte[] getKey() {
		return Arrays.copyOf(key, key.length);
	}
}
