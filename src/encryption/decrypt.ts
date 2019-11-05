import { decrypt as triplesecDecrypt } from 'triplesec'
import { decryptMnemonic } from 'blockstack/lib/encryption/wallet'

/**
 * Encrypt a raw mnemonic phrase with a password
 * @param data - Buffer or hex-encoded string of the encrypted mnemonic
 * @param password - Password for data
 * @return the raw mnemonic phrase
 */
export async function decrypt(dataBuffer: Buffer, password: string): Promise<string> {
  const result = await decryptMnemonic(dataBuffer, password, triplesecDecrypt)
  return result
}
