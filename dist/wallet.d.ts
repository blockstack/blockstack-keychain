import { BIP32Interface } from 'bip32';
import { IdentityKeyPair } from './utils';
import Identity from './identity';
export interface ConstructorOptions {
    identityPublicKeychain: string;
    bitcoinPublicKeychain: string;
    firstBitcoinAddress: string;
    identityKeypairs: IdentityKeyPair[];
    identityAddresses: string[];
    encryptedBackupPhrase: string;
}
export declare class Wallet {
    encryptedBackupPhrase: string;
    bitcoinPublicKeychain: string;
    firstBitcoinAddress: string;
    identityKeypairs: IdentityKeyPair[];
    identityAddresses: string[];
    identityPublicKeychain: string;
    identities: Identity[];
    constructor({ encryptedBackupPhrase, identityPublicKeychain, bitcoinPublicKeychain, firstBitcoinAddress, identityKeypairs, identityAddresses }: ConstructorOptions);
    static generate(password: string): Promise<Wallet>;
    static restore(password: string, backupPhrase: string): Promise<Wallet>;
    static createAccount(encryptedBackupPhrase: string, masterKeychain: BIP32Interface, identitiesToGenerate?: number): Wallet;
}
export default Wallet;
