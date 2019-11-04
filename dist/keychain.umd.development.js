(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('bip39'), require('bip32'), require('crypto-browserify'), require('bitcoinjs-lib'), require('blockstack'), require('jsontokens')) :
  typeof define === 'function' && define.amd ? define(['exports', 'bip39', 'bip32', 'crypto-browserify', 'bitcoinjs-lib', 'blockstack', 'jsontokens'], factory) :
  (global = global || self, factory(global['@blockstack/keychain'] = {}, global.bip39, global.bip32, global.cryptoBrowserify, global.bitcoinjsLib, global.blockstack, global.jsontokens));
}(this, (function (exports, bip39, bip32, cryptoBrowserify, bitcoinjsLib, blockstack, jsontokens) { 'use strict';

  function _extends() {
    _extends = Object.assign || function (target) {
      for (var i = 1; i < arguments.length; i++) {
        var source = arguments[i];

        for (var key in source) {
          if (Object.prototype.hasOwnProperty.call(source, key)) {
            target[key] = source[key];
          }
        }
      }

      return target;
    };

    return _extends.apply(this, arguments);
  }

  var AppNode =
  /*#__PURE__*/
  function () {
    function AppNode(hdNode, appDomain) {
      this.hdNode = hdNode;
      this.appDomain = appDomain;
    }

    var _proto = AppNode.prototype;

    _proto.getAppPrivateKey = function getAppPrivateKey() {
      if (!this.hdNode.privateKey) {
        throw new Error('Node does not have private key');
      }

      return this.hdNode.privateKey.toString('hex');
    };

    _proto.getAddress = function getAddress$1() {
      return getAddress(this.hdNode);
    };

    return AppNode;
  }();

  var AppsNode =
  /*#__PURE__*/
  function () {
    function AppsNode(appsHdNode, salt) {
      this.hdNode = appsHdNode;
      this.salt = salt;
    }

    var _proto = AppsNode.prototype;

    _proto.getNode = function getNode() {
      return this.hdNode;
    };

    _proto.getAppNode = function getAppNode(appDomain) {
      var hash = cryptoBrowserify.createHash('sha256').update("" + appDomain + this.salt).digest('hex');
      var appIndex = hashCode(hash);
      var appNode = this.hdNode.deriveHardened(appIndex);
      return new AppNode(appNode, appDomain);
    };

    _proto.toBase58 = function toBase58() {
      return this.hdNode.toBase58();
    };

    _proto.getSalt = function getSalt() {
      return this.salt;
    };

    return AppsNode;
  }();

  var APPS_NODE_INDEX = 0;
  var SIGNING_NODE_INDEX = 1;
  var ENCRYPTION_NODE_INDEX = 2;

  var IdentityAddressOwnerNode =
  /*#__PURE__*/
  function () {
    function IdentityAddressOwnerNode(ownerHdNode, salt) {
      this.hdNode = ownerHdNode;
      this.salt = salt;
    }

    var _proto = IdentityAddressOwnerNode.prototype;

    _proto.getNode = function getNode() {
      return this.hdNode;
    };

    _proto.getSalt = function getSalt() {
      return this.salt;
    };

    _proto.getIdentityKey = function getIdentityKey() {
      if (!this.hdNode.privateKey) {
        throw new Error('Node does not have private key');
      }

      return this.hdNode.privateKey.toString('hex');
    };

    _proto.getIdentityKeyID = function getIdentityKeyID() {
      return this.hdNode.publicKey.toString('hex');
    };

    _proto.getAppsNode = function getAppsNode() {
      return new AppsNode(this.hdNode.deriveHardened(APPS_NODE_INDEX), this.salt);
    };

    _proto.getAddress = function getAddress$1() {
      // return this.hdNode.getAddress()
      return getAddress(this.hdNode);
    };

    _proto.getEncryptionNode = function getEncryptionNode() {
      return this.hdNode.deriveHardened(ENCRYPTION_NODE_INDEX);
    };

    _proto.getSigningNode = function getSigningNode() {
      return this.hdNode.deriveHardened(SIGNING_NODE_INDEX);
    };

    return IdentityAddressOwnerNode;
  }();

  var IDENTITY_KEYCHAIN = 888;
  var BLOCKSTACK_ON_BITCOIN = 0;
  function getIdentityPrivateKeychain(masterKeychain) {
    return masterKeychain.deriveHardened(IDENTITY_KEYCHAIN).deriveHardened(BLOCKSTACK_ON_BITCOIN);
  }
  var EXTERNAL_ADDRESS = 'EXTERNAL_ADDRESS';
  var CHANGE_ADDRESS = 'CHANGE_ADDRESS';
  function getBitcoinPrivateKeychain(masterKeychain) {
    var BIP_44_PURPOSE = 44;
    var BITCOIN_COIN_TYPE = 0;
    var ACCOUNT_INDEX = 0;
    return masterKeychain.deriveHardened(BIP_44_PURPOSE).deriveHardened(BITCOIN_COIN_TYPE).deriveHardened(ACCOUNT_INDEX);
  }
  function getBitcoinAddressNode(bitcoinKeychain, addressIndex, chainType) {
    if (addressIndex === void 0) {
      addressIndex = 0;
    }

    if (chainType === void 0) {
      chainType = EXTERNAL_ADDRESS;
    }

    var chain = null;

    if (chainType === EXTERNAL_ADDRESS) {
      chain = 0;
    } else if (chainType === CHANGE_ADDRESS) {
      chain = 1;
    } else {
      throw new Error('Invalid chain type');
    }

    return bitcoinKeychain.derive(chain).derive(addressIndex);
  }
  function getIdentityOwnerAddressNode(identityPrivateKeychain, identityIndex) {
    if (identityIndex === void 0) {
      identityIndex = 0;
    }

    if (identityPrivateKeychain.isNeutered()) {
      throw new Error('You need the private key to generate identity addresses');
    }

    var publicKeyHex = identityPrivateKeychain.publicKey.toString('hex');
    var salt = cryptoBrowserify.createHash('sha256').update(publicKeyHex).digest('hex');
    return new IdentityAddressOwnerNode(identityPrivateKeychain.deriveHardened(identityIndex), salt);
  } // HDNode is no longer a part of bitcoinjs-lib
  // This function is taken from https://github.com/bitcoinjs/bitcoinjs-lib/pull/1073/files#diff-1f03b6ff764c499bfbdf841bf8fc113eR10

  function getAddress(node) {
    return bitcoinjsLib.address.toBase58Check(bitcoinjsLib.crypto.hash160(node.publicKey), bitcoinjsLib.networks.bitcoin.pubKeyHash);
  }
  function hashCode(string) {
    var hash = 0;
    if (string.length === 0) return hash;

    for (var i = 0; i < string.length; i++) {
      var character = string.charCodeAt(i);
      hash = (hash << 5) - hash + character;
      hash &= hash;
    }

    return hash & 0x7fffffff;
  }
  function deriveIdentityKeyPair(identityOwnerAddressNode) {
    var address = identityOwnerAddressNode.getAddress();
    var identityKey = identityOwnerAddressNode.getIdentityKey();
    var identityKeyID = identityOwnerAddressNode.getIdentityKeyID();
    var appsNode = identityOwnerAddressNode.getAppsNode();
    var keyPair = {
      key: identityKey,
      keyID: identityKeyID,
      address: address,
      appsNodeKey: appsNode.toBase58(),
      salt: appsNode.getSalt()
    };
    return keyPair;
  }
  function getBlockchainIdentities(masterKeychain, identitiesToGenerate) {
    var identityPrivateKeychainNode = getIdentityPrivateKeychain(masterKeychain);
    var bitcoinPrivateKeychainNode = getBitcoinPrivateKeychain(masterKeychain);
    var identityPublicKeychainNode = identityPrivateKeychainNode.neutered();
    var identityPublicKeychain = identityPublicKeychainNode.toBase58();
    var bitcoinPublicKeychainNode = bitcoinPrivateKeychainNode.neutered();
    var bitcoinPublicKeychain = bitcoinPublicKeychainNode.toBase58();
    var firstBitcoinAddress = getAddress(getBitcoinAddressNode(bitcoinPublicKeychainNode));
    var identityAddresses = [];
    var identityKeypairs = []; // We pre-generate a number of identity addresses so that we
    // don't have to prompt the user for the password on each new profile

    for (var addressIndex = 0; addressIndex < identitiesToGenerate; addressIndex++) {
      var identityOwnerAddressNode = getIdentityOwnerAddressNode(identityPrivateKeychainNode, addressIndex);
      var identityKeyPair = deriveIdentityKeyPair(identityOwnerAddressNode);
      identityKeypairs.push(identityKeyPair);
      identityAddresses.push(identityKeyPair.address);
    }

    return {
      identityPublicKeychain: identityPublicKeychain,
      bitcoinPublicKeychain: bitcoinPublicKeychain,
      firstBitcoinAddress: firstBitcoinAddress,
      identityAddresses: identityAddresses,
      identityKeypairs: identityKeypairs
    };
  }

  var encrypt = function encrypt(plaintextBuffer, password) {
    try {
      var mnemonic = plaintextBuffer.toString();
      return Promise.resolve(encryptMain(mnemonic, password)); // const encryptedBuffer = await encryptMnemonic(mnemonic, password);
      // return encryptedBuffer.toString("hex");
    } catch (e) {
      return Promise.reject(e);
    }
  };
  var encryptMain = function encryptMain(mnemonic, password) {
    try {
      // logger.debug("Encrypting from worker", mnemonic, password);
      return Promise.resolve(encryptMnemonic(mnemonic, password)).then(function (encryptedBuffer) {
        return encryptedBuffer.toString('hex');
      });
    } catch (e) {
      return Promise.reject(e);
    }
  };

  var encryptMnemonic = function encryptMnemonic(mnemonic, password) {
    try {
      // must be bip39 mnemonic
      if (!bip39.validateMnemonic(mnemonic)) {
        throw new Error('Not a valid bip39 nmemonic');
      } // normalize plaintext to fixed length byte string


      return Promise.resolve(normalizeMnemonic(mnemonic)).then(function (normalizedMnemonic) {
        var plaintextNormalized = Buffer.from(normalizedMnemonic, 'hex'); // AES-128-CBC with SHA256 HMAC

        var salt = cryptoBrowserify.randomBytes(16);
        var keysAndIV = cryptoBrowserify.pbkdf2Sync(password, salt, 100000, 48, 'sha512');
        var encKey = keysAndIV.slice(0, 16);
        var macKey = keysAndIV.slice(16, 32);
        var iv = keysAndIV.slice(32, 48);
        var cipher = cryptoBrowserify.createCipheriv('aes-128-cbc', encKey, iv);
        var cipherText = cipher.update(plaintextNormalized).toString('hex');
        cipherText += cipher["final"]('hex');
        var hmacPayload = Buffer.concat([salt, Buffer.from(cipherText, 'hex')]);
        var hmac = cryptoBrowserify.createHmac('sha256', macKey);
        hmac.update(hmacPayload);
        var hmacDigest = hmac.digest();
        return Buffer.concat([salt, hmacDigest, Buffer.from(cipherText, 'hex')]);
      });
    } catch (e) {
      return Promise.reject(e);
    }
  };

  var normalizeMnemonic = function normalizeMnemonic(mnemonic) {
    try {
      // Note: Future-proofing with async wrappers around any synchronous cryptographic code.
      return Promise.resolve(bip39.mnemonicToEntropy(mnemonic));
    } catch (e) {
      return Promise.reject(e);
    }
  };

  var getHubInfo = function getHubInfo(hubUrl) {
    try {
      return Promise.resolve(fetch(hubUrl + "/hub_info")).then(function (response) {
        return Promise.resolve(response.json());
      });
    } catch (e) {
      return Promise.reject(e);
    }
  };
  var getHubPrefix = function getHubPrefix(hubUrl) {
    try {
      return Promise.resolve(getHubInfo(hubUrl)).then(function (_ref) {
        var read_url_prefix = _ref.read_url_prefix;
        return read_url_prefix;
      });
    } catch (e) {
      return Promise.reject(e);
    }
  };
  var makeGaiaAssociationToken = function makeGaiaAssociationToken(secretKeyHex, childPublicKeyHex) {
    var LIFETIME_SECONDS = 365 * 24 * 3600;
    var signerKeyHex = secretKeyHex.slice(0, 64);
    var compressedPublicKeyHex = blockstack.getPublicKeyFromPrivate(signerKeyHex);
    var salt = cryptoBrowserify.randomBytes(16).toString('hex');
    var payload = {
      childToAssociate: childPublicKeyHex,
      iss: compressedPublicKeyHex,
      exp: LIFETIME_SECONDS + new Date().getTime() / 1000,
      iat: Date.now() / 1000,
      salt: salt
    };
    var token = new jsontokens.TokenSigner('ES256K', signerKeyHex).sign(payload);
    return token;
  };

  var Identity =
  /*#__PURE__*/
  function () {
    function Identity(_ref) {
      var keyPair = _ref.keyPair,
          address = _ref.address;
      this.keyPair = keyPair;
      this.address = address;
    }

    var _proto = Identity.prototype;

    _proto.makeAuthResponse = function makeAuthResponse(_ref2) {
      var appDomain = _ref2.appDomain,
          gaiaUrl = _ref2.gaiaUrl,
          transitPublicKey = _ref2.transitPublicKey,
          profile = _ref2.profile;

      try {
        var _this2 = this;

        var appPrivateKey = _this2.appPrivateKey(appDomain);

        return Promise.resolve(getHubPrefix(gaiaUrl)).then(function (hubPrefix) {
          return Promise.resolve(_this2.profileUrl(hubPrefix)).then(function (profileUrl) {
            // const appBucketUrl = await getAppBucketUrl(gaiaUrl, appPrivateKey)
            var compressedAppPublicKey = blockstack.getPublicKeyFromPrivate(appPrivateKey.slice(0, 64));
            var associationToken = makeGaiaAssociationToken(_this2.keyPair.key, compressedAppPublicKey);
            return blockstack.makeAuthResponse(_this2.keyPair.key, profile || {}, '', {
              profileUrl: profileUrl
            }, undefined, appPrivateKey, undefined, transitPublicKey, gaiaUrl, undefined, associationToken);
          });
        });
      } catch (e) {
        return Promise.reject(e);
      }
    };

    _proto.appPrivateKey = function appPrivateKey(appDomain) {
      var _this$keyPair = this.keyPair,
          salt = _this$keyPair.salt,
          appsNodeKey = _this$keyPair.appsNodeKey;
      var appsNode = new AppsNode(bip32.fromBase58(appsNodeKey), salt);
      var appPrivateKey = appsNode.getAppNode(appDomain).getAppPrivateKey();
      return appPrivateKey;
    } // eslint-disable-next-line @typescript-eslint/require-await
    ;

    _proto.profileUrl = function profileUrl(gaiaUrl) {
      try {
        var _this4 = this;

        // future proofing for code that may require network requests to find profile
        return Promise.resolve("" + gaiaUrl + _this4.address + "/profile.json");
      } catch (e) {
        return Promise.reject(e);
      }
    };

    return Identity;
  }();

  var Wallet =
  /*#__PURE__*/
  function () {
    function Wallet(_ref) {
      var encryptedBackupPhrase = _ref.encryptedBackupPhrase,
          identityPublicKeychain = _ref.identityPublicKeychain,
          bitcoinPublicKeychain = _ref.bitcoinPublicKeychain,
          firstBitcoinAddress = _ref.firstBitcoinAddress,
          identityKeypairs = _ref.identityKeypairs,
          identityAddresses = _ref.identityAddresses;
      this.encryptedBackupPhrase = encryptedBackupPhrase;
      this.identityPublicKeychain = identityPublicKeychain;
      this.bitcoinPublicKeychain = bitcoinPublicKeychain;
      this.firstBitcoinAddress = firstBitcoinAddress;
      this.identityKeypairs = identityKeypairs;
      this.identityAddresses = identityAddresses;
      var identities = [];
      identityKeypairs.forEach(function (keyPair, index) {
        var address = identityAddresses[index];
        var identity = new Identity({
          keyPair: keyPair,
          address: address
        });
        identities.push(identity);
      });
      this.identities = identities;
    }

    Wallet.generate = function generate(password) {
      try {
        var _this2 = this;

        var STRENGTH = 128; // 128 bits generates a 12 word mnemonic

        var backupPhrase = bip39.generateMnemonic(STRENGTH, cryptoBrowserify.randomBytes);
        return Promise.resolve(bip39.mnemonicToSeed(backupPhrase)).then(function (seedBuffer) {
          var masterKeychain = bip32.fromSeed(seedBuffer);
          return Promise.resolve(encrypt(Buffer.from(backupPhrase), password)).then(function (ciphertextBuffer) {
            var encryptedBackupPhrase = ciphertextBuffer.toString();
            return _this2.createAccount(encryptedBackupPhrase, masterKeychain);
          });
        });
      } catch (e) {
        return Promise.reject(e);
      }
    };

    Wallet.restore = function restore(password, backupPhrase) {
      try {
        var _this4 = this;

        if (!bip39.validateMnemonic(backupPhrase)) {
          throw new Error('Invalid mnemonic used to restore wallet');
        }

        return Promise.resolve(bip39.mnemonicToSeed(backupPhrase)).then(function (seedBuffer) {
          var masterKeychain = bip32.fromSeed(seedBuffer);
          return Promise.resolve(encrypt(Buffer.from(backupPhrase), password)).then(function (ciphertextBuffer) {
            var encryptedBackupPhrase = ciphertextBuffer.toString();
            return _this4.createAccount(encryptedBackupPhrase, masterKeychain);
          });
        });
      } catch (e) {
        return Promise.reject(e);
      }
    };

    Wallet.createAccount = function createAccount(encryptedBackupPhrase, masterKeychain, identitiesToGenerate) {
      if (identitiesToGenerate === void 0) {
        identitiesToGenerate = 1;
      }

      var walletAttrs = getBlockchainIdentities(masterKeychain, identitiesToGenerate);
      return new this(_extends({}, walletAttrs, {
        encryptedBackupPhrase: encryptedBackupPhrase
      }));
    };

    return Wallet;
  }();

  var index = {
    Wallet: Wallet
  };

  exports.default = index;

})));
//# sourceMappingURL=keychain.umd.development.js.map
