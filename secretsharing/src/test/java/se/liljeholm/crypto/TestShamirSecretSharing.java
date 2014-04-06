package se.liljeholm.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author torbjorn
 * @since 20 mar 2014 13:41:26
 *
 */
public class TestShamirSecretSharing {
	private SecretSharing secretSharing;
	private byte[] key;
	
	@Before
	public void setUp() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey secretKey = keyGenerator.generateKey();
		key = secretKey.getEncoded();
	}
	
	@Test
	public void testTwoShares() {
		testShamirSecretSharing(2, 5);
	}
	
	@Test
	public void testThreeShares() {
		testShamirSecretSharing(3, 5);
	}
	
	private void testShamirSecretSharing(int threshold, int participants) {
		secretSharing = new ShamirSecretSharing(threshold, participants);
		List<Share> shares = secretSharing.share(key);
		byte[] assembledKey = secretSharing.assemble(shares);
		Assert.assertArrayEquals(key, assembledKey);
	}
}
