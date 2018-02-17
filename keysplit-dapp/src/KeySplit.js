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
    var c = crypto.createCipher("aes128", password);
    var encKey = c.update(key, 'hex', 'hex');
    encKey += c.final('hex')
    var shares = secrets.share(encKey, shareCount, threshold);
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
    var encKey = secrets.combine(shares);
    var d = crypto.createDecipher("aes128", password);
    var rawKey = d.update(encKey, "hex", "hex");
    rawKey += d.final("hex");
    return bip39.entropyToMnemonic(rawKey);
  }
};

export default KeySplit;
