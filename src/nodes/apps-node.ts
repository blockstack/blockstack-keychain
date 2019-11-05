import { BIP32Interface } from 'bitcoinjs-lib'
import { createSha2Hash } from 'blockstack/lib/encryption/sha2Hash'
import { hashCode } from '../utils'
import AppNode from './app-node'

export default class AppsNode {
  hdNode: BIP32Interface

  salt: string

  constructor(appsHdNode: BIP32Interface, salt: string) {
    this.hdNode = appsHdNode
    this.salt = salt
  }

  getNode() {
    return this.hdNode
  }

  async getAppNode(appDomain: string) {
    const sha2Hash = await createSha2Hash()
    const hashData = await sha2Hash.digest(Buffer.from(`${appDomain}${this.salt}`))
    const hash = hashData.toString('hex')
    const appIndex = hashCode(hash)
    const appNode = this.hdNode.deriveHardened(appIndex)
    return new AppNode(appNode, appDomain)
  }

  toBase58() {
    return this.hdNode.toBase58()
  }

  getSalt() {
    return this.salt
  }
}
