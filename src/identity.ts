import { fromBase58 } from 'bip32'
import { getAppBucketUrl, getPublicKeyFromPrivate, makeAuthResponse } from 'blockstack'

import { IdentityKeyPair } from './utils/index'
import { getHubPrefix, makeGaiaAssociationToken } from './utils/gaia'
import AppsNode from './nodes/apps-node'

export default class Identity {
  public keyPair: IdentityKeyPair
  public address: string

  constructor({ keyPair, address }: { keyPair: IdentityKeyPair; address: string; }) {
    this.keyPair = keyPair
    this.address = address
  }

  async makeAuthResponse({ appDomain, gaiaUrl, transitPublicKey, profile }: { 
    appDomain: string
    gaiaUrl: string
    transitPublicKey: string
    profile?: {}
  }) {
    const appPrivateKey = this.appPrivateKey(appDomain)
    const hubPrefix = await getHubPrefix(gaiaUrl)
    const profileUrl = await this.profileUrl(hubPrefix)
    // const appBucketUrl = await getAppBucketUrl(gaiaUrl, appPrivateKey)

    const compressedAppPublicKey = getPublicKeyFromPrivate(appPrivateKey.slice(0, 64))
    const associationToken = makeGaiaAssociationToken(this.keyPair.key, compressedAppPublicKey)

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

    // return {
    //   appPrivateKey,
    //   profileUrl,
    //   appBucketUrl,
    //   associationToken
    // }
  }

  appPrivateKey(appDomain: string) {
    const { salt, appsNodeKey } = this.keyPair
    const appsNode = new AppsNode(fromBase58(appsNodeKey), salt)
    const appPrivateKey = appsNode.getAppNode(appDomain).getAppPrivateKey()
    return appPrivateKey
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async profileUrl(gaiaUrl: string) {
    // future proofing for code that may require network requests to find profile
    return `${gaiaUrl}${this.address}/profile.json`
  }
}
