import Wallet from '../src/wallet'

const getIdentity = async () => {
  const seed = 'sound idle panel often situate develop unit text design antenna '
    + 'vendor screen opinion balcony share trigger accuse scatter visa uniform brass '
    + 'update opinion media'
  const password = 'password'
  const wallet = await Wallet.restore(password, seed)
  const [identity] = wallet.identities
  return identity
}

test('generates an auth response', async () => {
  const identity = await getIdentity()
  const appDomain = 'https://banter.pub'
  const gaiaUrl = 'https://hub.blockstack.org'
  await identity.makeAuthResponse({ appDomain, gaiaUrl })
  // console.log(authResponse)
})

test('generates an app private key', async () => {
  const expectedKey = '6f8b6a170f8b2ee57df5ead49b0f4c8acde05f9e1c4c6ef8223d6a42fabfa314'
  const identity = await getIdentity()
  const appPrivateKey = identity.appPrivateKey('https://banter.pub')
  expect(appPrivateKey).toEqual(expectedKey)
})

test('gets default profile URL', async () => {
  const identity = await getIdentity()
  const gaiaUrl = 'https://hub.blockstack.org'
  expect(await identity.profileUrl(gaiaUrl)).toEqual('https://hub.blockstack.org/1JeTQ5cQjsD57YGcsVFhwT7iuQUXJR6BSk/profile.json')
})
