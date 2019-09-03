import { fromBase58 } from 'bip32'
import { getAppBucketUrl } from 'blockstack'

import { IdentityKeyPair } from './utils/index'
import { getHubPrefix } from './utils/gaia'
import AppsNode from './nodes/apps-node'

export default class Identity {
  public keyPair: IdentityKeyPair
  public address: string

  constructor({ keyPair, address }: { keyPair: IdentityKeyPair; address: string; }) {
    this.keyPair = keyPair
    this.address = address
  }

  async makeAuthResponse({ appDomain, gaiaUrl }: { appDomain: string, gaiaUrl: string }) {
    const appPrivateKey = this.appPrivateKey(appDomain)
    const hubPrefix = await getHubPrefix(gaiaUrl)
    const profileUrl = await this.profileUrl(hubPrefix)
    const appBucketUrl = await getAppBucketUrl(gaiaUrl, appPrivateKey)
    return {
      appPrivateKey,
      profileUrl,
      appBucketUrl
    }
  }

  appPrivateKey(appDomain: string) {
    const { salt, appsNodeKey } = this.keyPair
    const appsNode = new AppsNode(fromBase58(appsNodeKey), salt)
    const appPrivateKey = appsNode.getAppNode(appDomain).getAppPrivateKey()
    return appPrivateKey
  }

  async profileUrl(gaiaUrl: string) {
    return `${gaiaUrl}/${this.address}/profile.json`
  }
}
