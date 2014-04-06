package se.liljeholm.crypto;


import java.util.List;

/**
 * @author torbjorn
 * @since 28 feb 2014 12:07:11
 *
 */
public interface SecretSharing {

	/**
	 * Takes the input and splits it into specified number of parts.
	 * 
	 * @param secret the secret to be divided
	 * @return a list of secrets required to recreate the secret.
	 */
	List<Share> share(byte[] secret);

	/**
	 * Assemble the secret using the supplied secret key parts.
	 * 
	 * @param parts the list of secret key parts needed to recreate the secret
	 * @return the secret key
	 */
	byte[] assemble(List<Share> shares);
}
