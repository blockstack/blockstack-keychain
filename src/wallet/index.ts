import { generateMnemonic, mnemonicToSeed } from 'bip39'
import { bip32, BIP32Interface } from 'bitcoinjs-lib'
import { randomBytes } from 'blockstack/lib/encryption/cryptoRandom'

import { getBlockchainIdentities, IdentityKeyPair, makeIdentity } from '../utils'
import { encrypt} from '../encryption/encrypt'
import Identity from '../identity'
import { decrypt } from '../encryption/decrypt'
import { connectToGaiaHub } from 'blockstack'

const CONFIG_INDEX = 45

interface ConfigApp {
  origin: string
  scopes: string[]
  lastLoginAt: number
  appIcon: string
  name: string
}

interface ConfigIdentity {
  username?: string
  apps: {
    [origin: string]: ConfigApp
  }
}

export interface WalletConfig {
  identities: ConfigIdentity[]
}

export interface ConstructorOptions {
  identityPublicKeychain: string
  bitcoinPublicKeychain: string
  firstBitcoinAddress: string
  identityKeypairs: IdentityKeyPair[]
  identityAddresses: string[]
  encryptedBackupPhrase: string
  identities: Identity[]
  configPrivateKey: string
}

export class Wallet {
  encryptedBackupPhrase: string
  bitcoinPublicKeychain: string
  firstBitcoinAddress: string
  identityKeypairs: IdentityKeyPair[]
  identityAddresses: string[]
  identityPublicKeychain: string
  identities: Identity[]
  configPrivateKey: string
  walletConfig?: WalletConfig

  constructor({
    encryptedBackupPhrase,
    identityPublicKeychain,
    bitcoinPublicKeychain,
    firstBitcoinAddress,
    identityKeypairs,
    identityAddresses,
    identities,
    configPrivateKey
  }: ConstructorOptions) {
    this.encryptedBackupPhrase = encryptedBackupPhrase
    this.identityPublicKeychain = identityPublicKeychain
    this.bitcoinPublicKeychain = bitcoinPublicKeychain
    this.firstBitcoinAddress = firstBitcoinAddress
    this.identityKeypairs = identityKeypairs
    this.identityAddresses = identityAddresses
    this.identities = identities.map((identity) => new Identity(identity))
    this.configPrivateKey = configPrivateKey
  }

  static async generate(password: string) {
    const STRENGTH = 128 // 128 bits generates a 12 word mnemonic
    const backupPhrase = generateMnemonic(STRENGTH, randomBytes)
    const seedBuffer = await mnemonicToSeed(backupPhrase)
    const masterKeychain = bip32.fromSeed(seedBuffer)
    const ciphertextBuffer = await encrypt(backupPhrase, password)
    const encryptedBackupPhrase = ciphertextBuffer.toString('hex')
    return this.createAccount(encryptedBackupPhrase, masterKeychain)
  }

  static async restore(password: string, backupPhrase: string) {
    const encryptedMnemonic = await encrypt(backupPhrase, password)
    const encryptedMnemonicHex = encryptedMnemonic.toString('hex')
    const seedBuffer = await mnemonicToSeed(backupPhrase)
    const rootNode = bip32.fromSeed(seedBuffer)
    return this.createAccount(encryptedMnemonicHex, rootNode)
  }

  static async createAccount(encryptedBackupPhrase: string, masterKeychain: BIP32Interface, identitiesToGenerate = 1) {
    const configPrivateKey = masterKeychain.deriveHardened(CONFIG_INDEX).privateKey?.toString('hex') as string
    const walletAttrs = await getBlockchainIdentities(masterKeychain, identitiesToGenerate)
    return new this({
      ...walletAttrs,
      configPrivateKey,
      encryptedBackupPhrase
    })
  }

  async createNewIdentity(password: string) {
    const plainTextBuffer = await decrypt(Buffer.from(this.encryptedBackupPhrase, 'hex'), password)
    const seed = await mnemonicToSeed(plainTextBuffer)
    const rootNode = bip32.fromSeed(seed)
    const index = this.identities.length
    const identity = await makeIdentity(rootNode, index)
    this.identities.push(identity)
    this.identityKeypairs.push(identity.keyPair)
    this.identityAddresses.push(identity.address)
    return identity
  }

  async fetchConfig(gaiaHubUrl: string): Promise<WalletConfig | null> {
    try {
      const gaiaConfig = await connectToGaiaHub(gaiaHubUrl, this.configPrivateKey)
      // await putFile('wallet-config.json', JSON.stringify(this.wall))
      const response = await fetch(`${gaiaConfig.url_prefix}/${gaiaConfig.address}/wallet-config.json`)
      const config: WalletConfig = await response.json() 
      this.walletConfig = config
      return config
    } catch (error) {
      // console.error(error)
      return null
    }
  }
}

export default Wallet
