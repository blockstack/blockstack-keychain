/// <reference types="node" />
export declare function decryptMain(hexEncryptedKey: string, password: string): Promise<string>;
export declare function decrypt(dataBuffer: Buffer, password: string): Promise<Buffer>;
