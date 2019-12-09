import { bip32 } from 'bitcoinjs-lib'
import { getPublicKeyFromPrivate } from 'blockstack/lib/keys'
import { makeAuthResponse } from 'blockstack/lib/auth/authMessages'

import { IdentityKeyPair } from './utils/index'
import { getHubPrefix, makeGaiaAssociationToken } from './utils/gaia'
import IdentityAddressOwnerNode from './nodes/identity-address-owner-node'

interface IdentityConstructorOptions {
  keyPair: IdentityKeyPair
  address: string
  usernames?: string[]
  defaultUsername?: string
}

export default class Identity {
  public keyPair: IdentityKeyPair
  public address: string
  public defaultUsername?: string
  public usernames: string[]

  constructor({ keyPair, address, usernames, defaultUsername }: IdentityConstructorOptions) {
    this.keyPair = keyPair
    this.address = address
    this.usernames = usernames || []
    this.defaultUsername = defaultUsername
  }

  async makeAuthResponse({ appDomain, gaiaUrl, transitPublicKey, profile }: { 
    appDomain: string
    gaiaUrl: string
    transitPublicKey: string
    profile?: {}
  }) {
    const appPrivateKey = await this.appPrivateKey(appDomain)
    const hubPrefix = await getHubPrefix(gaiaUrl)
    const profileUrl = await this.profileUrl(hubPrefix)
    // const appBucketUrl = await getAppBucketUrl(gaiaUrl, appPrivateKey)

    const compressedAppPublicKey = getPublicKeyFromPrivate(appPrivateKey.slice(0, 64))
    const associationToken = await makeGaiaAssociationToken(this.keyPair.key, compressedAppPublicKey)

    return makeAuthResponse(
      this.keyPair.key,
      profile || {},
      '',
      {
        profileUrl
      },
      undefined,
      appPrivateKey,
      undefined,
      transitPublicKey,
      gaiaUrl,
      undefined,
      associationToken
    )
  }

  async appPrivateKey(appDomain: string) {
    const { salt, appsNodeKey } = this.keyPair
    const appsNode = new IdentityAddressOwnerNode(bip32.fromBase58(appsNodeKey), salt)
    return appsNode.getAppPrivateKey(appDomain)
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async profileUrl(gaiaUrl: string) {
    // future proofing for code that may require network requests to find profile
    return `${gaiaUrl}${this.address}/profile.json`
  }

  /**
   * Fetch existing information related to this identity, like username and profile information
   */
  async refresh() {
    try {
      const getNamesUrl = `https://core.blockstack.org/v1/addresses/bitcoin/${this.address}`
      const res = await fetch(getNamesUrl)
      const data = await res.json()
      const { names }: { names: string[]; } = data
      if (names[0] && !this.defaultUsername) {
        this.defaultUsername = names[0]
      }
      names.forEach((name) => {
        const existingIndex = this.usernames.findIndex(u => u === name)
        if (existingIndex === -1) {
          this.usernames.push(name)
        }
      })
      return
    } catch (error) {
      return
    }
  }
}
