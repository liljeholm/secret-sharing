package se.liljeholm.crypto;


/**
 * @author torbjorn
 * @since 20 mar 2014 12:59:44
 * 
 */
public class Share {
	private int share;
	private byte[] key;

	public Share(int share, byte[] key) {
		super();
		this.share = share;
		this.key = key;
	}

	public int getShare() {
		return share;
	}

	public byte[] getKey() {
		return key;
	}
}
