import { BIP32Interface } from 'bip32';
import AppNode from './app-node';
export default class AppsNode {
    hdNode: BIP32Interface;
    salt: string;
    constructor(appsHdNode: BIP32Interface, salt: string);
    getNode(): BIP32Interface;
    getAppNode(appDomain: string): AppNode;
    toBase58(): string;
    getSalt(): string;
}
