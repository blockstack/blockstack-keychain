import { BIP32Interface } from 'bip32';
import IdentityAddressOwnerNode from '../nodes/identity-address-owner-node';
export declare function getIdentityPrivateKeychain(masterKeychain: BIP32Interface): BIP32Interface;
export declare function getBitcoinPrivateKeychain(masterKeychain: BIP32Interface): BIP32Interface;
export declare function getBitcoinAddressNode(bitcoinKeychain: BIP32Interface, addressIndex?: number, chainType?: string): BIP32Interface;
export declare function getIdentityOwnerAddressNode(identityPrivateKeychain: BIP32Interface, identityIndex?: number): IdentityAddressOwnerNode;
export declare function getAddress(node: BIP32Interface): string;
export declare function hashCode(string: string): number;
export interface IdentityKeyPair {
    key: string;
    keyID: string;
    address: string;
    appsNodeKey: string;
    salt: string;
}
export declare function deriveIdentityKeyPair(identityOwnerAddressNode: IdentityAddressOwnerNode): IdentityKeyPair;
export declare function getBlockchainIdentities(masterKeychain: BIP32Interface, identitiesToGenerate: number): {
    identityPublicKeychain: string;
    bitcoinPublicKeychain: string;
    firstBitcoinAddress: string;
    identityAddresses: string[];
    identityKeypairs: IdentityKeyPair[];
};
