import { signProfileToken, wrapProfileToken, connectToGaiaHub } from 'blockstack'
import { IdentityKeyPair } from './utils'
import Identity from './identity'
import { uploadToGaiaHub } from 'blockstack/lib/storage/hub'

export const DEFAULT_PROFILE = {
  '@type': 'Person',
  '@context': 'http://schema.org'
}

const DEFAULT_PROFILE_FILE_NAME = 'profile.json'

export async function signProfileForUpload(profile: any, keypair: IdentityKeyPair) {
  const privateKey = keypair.key
  const publicKey = keypair.keyID

  const token = await signProfileToken(profile, privateKey, { publicKey })
  const tokenRecord = wrapProfileToken(token)
  const tokenRecords = [tokenRecord]
  return JSON.stringify(tokenRecords, null, 2)
}

export async function uploadProfile(
  gaiaHubUrl: string,
  identity: Identity,
  signedProfileTokenData: string
) {
  const identityHubConfig = await connectToGaiaHub(gaiaHubUrl, identity.keyPair.key)

  return uploadToGaiaHub(DEFAULT_PROFILE_FILE_NAME, signedProfileTokenData, identityHubConfig, 'application/json')
}
