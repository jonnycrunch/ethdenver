import secrets from 'secrets.js-next';
import bip39 from 'bip39';
import {entropyToMnemonic} from './wordEncode.js';
import {mnemonicToEntropy} from './wordEncode.js';
import crypto from 'crypto';

function repeat(char, number) {
  var string = "";
  for(var i = 0; i < number; i++) {
    string += char;
  }
  return string;
}

var KeySplit = {
  mnemonicToSSS(mnemonic, shareCount, threshold, password) {
    var key = bip39.mnemonicToEntropy(mnemonic);
    var salt = crypto.randomBytes(8);
    var pbkdf2Pass = crypto.pbkdf2Sync(password, salt, 100000, 128, 'sha512');
    var c = crypto.createCipher("aes128", pbkdf2Pass);
    var encKey = c.update(key, 'hex', 'hex');
    encKey += c.final('hex')
    var splitVal = salt.toString("hex") + encKey;
    var shares = secrets.share(splitVal, shareCount, threshold);
    var mnemonicShares = [];
    for(var share of shares) {
      mnemonicShares.push(entropyToMnemonic(share + "000"));
    }
    return mnemonicShares
  },
  combineSSS(mnemonicShares, password) {
    var shares = [];
    for(var share of mnemonicShares) {
      var shareHex = mnemonicToEntropy(share);
      shares.push(shareHex.slice(0, shareHex.length - 3));
    }
    var splitVal = secrets.combine(shares);
    var salt = new Buffer(splitVal.slice(0, 16), "hex");
    var encKey = splitVal.slice(16);
    var pbkdf2Pass = crypto.pbkdf2Sync(password, salt, 100000, 128, 'sha512');
    var d = crypto.createDecipher("aes128", pbkdf2Pass);
    var rawKey = d.update(encKey, "hex", "hex");
    rawKey += d.final("hex");
    return bip39.entropyToMnemonic(rawKey);
  }
};

export default KeySplit;
