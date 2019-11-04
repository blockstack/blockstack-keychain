/// <reference types="node" />
export declare function encryptMain(mnemonic: string, password: string): Promise<string>;
export declare function encrypt(plaintextBuffer: Buffer, password: string): Promise<string>;
