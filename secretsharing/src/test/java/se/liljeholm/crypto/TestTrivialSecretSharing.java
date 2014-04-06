package se.liljeholm.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * @author torbjorn
 * @since 28 feb 2014 12:44:28
 *
 */
public class TestTrivialSecretSharing {
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
		testTrivialSharing(2);
	}
	
	@Test
	public void testThreeShares() {
		testTrivialSharing(3);
	}
	
	private void testTrivialSharing(int participants) {
		secretSharing = new TrivialSecretSharing(participants);
		List<Share> shares = secretSharing.share(key);
		byte[] assembledKey = secretSharing.assemble(shares);
		Assert.assertArrayEquals(key, assembledKey);
	}
}
