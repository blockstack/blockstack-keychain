import { signProfileForUpload, DEFAULT_PROFILE } from '../src/profiles'
import { getIdentity } from './helpers'
import { decodeToken, TokenVerifier } from 'jsontokens'

describe('signProfileForUpload', () => {
  it('should create a signed JSON string', async () => {
    const identity = await getIdentity()
    const signedJSON = await signProfileForUpload(DEFAULT_PROFILE, identity.keyPair)
    const [data] = JSON.parse(signedJSON)
    expect(data.token).not.toBeFalsy()
    const { claim } = data.decodedToken.payload
    expect(claim).toEqual(DEFAULT_PROFILE)
    const decoded = decodeToken(data.token)
    expect(decoded.payload).toEqual(data.decodedToken.payload)
    const verifier = new TokenVerifier('ES256K', data.decodedToken.payload.issuer.publicKey)
    expect(verifier.verify(data.token)).toBeTruthy()
  })
})
