import { signProfileToken, wrapProfileToken, connectToGaiaHub, makeProfileZoneFile } from 'blockstack'
import { IdentityKeyPair } from './utils'
import Identity from './identity'
import { uploadToGaiaHub } from 'blockstack/lib/storage/hub'

export const DEFAULT_PROFILE = {
  '@type': 'Person',
  '@context': 'http://schema.org'
}

const DEFAULT_PROFILE_FILE_NAME = 'profile.json'

enum Subdomains {
  TEST = 'test-personal.id',
  BLOCKSTACK = 'id.blockstack'
}

// interface Registrars {
//   [Subdomains.BLOCKSTACK]: {
//     registerUrl: string
//     apiUrl: string
//   }
//   [Subdomains.TEST]
// }

export const registrars = {
  [Subdomains.TEST]: {
    registerUrl: 'https://test-registrar.blockstack.org/register',
    apiUrl: 'https://test-registrar.blockstack.org/v1/names'
  },
  [Subdomains.BLOCKSTACK]: {
    registerUrl: 'https://registrar.blockstack.org/register',
    apiUrl: 'https://registrar.blockstack.org/v1/names'
  }
}

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

interface SendToRegistrarParams {
  username: string
  subdomain: Subdomains
  zoneFile: string
  identity: Identity
}

const sendUsernameToRegistrar = async ({
  username,
  subdomain,
  zoneFile,
  identity
}: SendToRegistrarParams) => {
  const { registerUrl } = registrars[subdomain]

  const registrationRequestBody = JSON.stringify({
    name: username,
    owner_address: identity.address,
    zonefile: zoneFile
  })

  const requestHeaders = {
    Accept: 'application/json',
    'Content-Type': 'application/json'
  }

  const response = await fetch(registerUrl, {
    method: 'POST',
    headers: requestHeaders,
    body: registrationRequestBody
  })

  if (!response.ok) {
    return Promise.reject({
      error: 'Failed to register username',
      status: response.status
    })
  }

  return response.json()
}

interface RegisterParams {
  identity: Identity
  gaiaHubUrl: string
  username: string
  subdomain: Subdomains
}

export const registerSubdomain = async ({
  identity,
  gaiaHubUrl,
  username,
  subdomain,
}: RegisterParams) => {
  // const profile = identity.profile || DEFAULT_PROFILE
  const profile = DEFAULT_PROFILE
  const signedProfileTokenData = await signProfileForUpload(profile, identity.keyPair)
  const profileUrl = await uploadProfile(gaiaHubUrl, identity, signedProfileTokenData)
  const tokenFileUrl = profileUrl
  const zoneFile = makeProfileZoneFile(username, tokenFileUrl)
  await sendUsernameToRegistrar({
    username,
    subdomain,
    zoneFile,
    identity
  })
  // eslint-disable-next-line require-atomic-updates
  identity.username = `${username}.${subdomain}`
  return identity
}
