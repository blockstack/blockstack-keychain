import { IdentityKeyPair } from './utils'

export default class Identity {
  public keyPair: IdentityKeyPair
  public address: string

  constructor({ keyPair, address }: { keyPair: IdentityKeyPair; address: string; }) {
    this.keyPair = keyPair
    this.address = address
  }
}
