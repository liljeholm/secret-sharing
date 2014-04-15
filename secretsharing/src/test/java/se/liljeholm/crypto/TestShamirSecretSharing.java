package se.liljeholm.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
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
//		key = new byte[] { 42 };
	}
	
	@Test
	public void testTwoShares() {
		testShamirSecretSharing(2, 10);
	}
	
	@Test
	public void testThreeShares() {
		testShamirSecretSharing(3, 5);
	}
	
	private void testShamirSecretSharing(int threshold, int participants) {
		secretSharing = new ShamirSecretSharing(threshold, participants);
		List<Share> shares = secretSharing.share(key);
		List<Share> sharesSubset = new ArrayList<>();
		for (int i = 0; i < threshold; i++) {
			sharesSubset.add(shares.get(i));
		}
		byte[] assembledKey = secretSharing.assemble(sharesSubset);
		Assert.assertArrayEquals(key, assembledKey);
	}
}
