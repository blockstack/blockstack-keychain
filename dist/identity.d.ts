import { IdentityKeyPair } from './utils/index';
export default class Identity {
    keyPair: IdentityKeyPair;
    address: string;
    constructor({ keyPair, address }: {
        keyPair: IdentityKeyPair;
        address: string;
    });
    makeAuthResponse({ appDomain, gaiaUrl, transitPublicKey, profile }: {
        appDomain: string;
        gaiaUrl: string;
        transitPublicKey: string;
        profile?: {};
    }): Promise<string>;
    appPrivateKey(appDomain: string): string;
    profileUrl(gaiaUrl: string): Promise<string>;
}
