import { BIP32Interface } from 'bip32';
export default class AppNode {
    hdNode: BIP32Interface;
    appDomain: string;
    constructor(hdNode: BIP32Interface, appDomain: string);
    getAppPrivateKey(): string;
    getAddress(): string;
}
