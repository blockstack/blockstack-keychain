import { BIP32Interface } from 'bip32';
import AppsNode from './apps-node';
export default class IdentityAddressOwnerNode {
    hdNode: BIP32Interface;
    salt: string;
    constructor(ownerHdNode: BIP32Interface, salt: string);
    getNode(): BIP32Interface;
    getSalt(): string;
    getIdentityKey(): string;
    getIdentityKeyID(): string;
    getAppsNode(): AppsNode;
    getAddress(): string;
    getEncryptionNode(): BIP32Interface;
    getSigningNode(): BIP32Interface;
}
