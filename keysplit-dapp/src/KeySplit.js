import secrets from 'secrets.js-next';
import bip39 from 'bip39';

function repeat(char, number) {
  var string = "";
  for(var i = 0; i < number; i++) {
    string += char;
  }
  return string;
}

var KeySplit = {
  mnemonicToSSS(mnemonic, shareCount, threshold) {
    var key = bip39.mnemonicToEntropy(mnemonic);
    var shares = secrets.share(key, shareCount, threshold);
    console.log(shares);
    var mnemonicShares = [];
    for(var share of shares) {
      share += repeat("0", 8 - (share.length % 8));
      console.log(share);
      mnemonicShares.push(bip39.entropyToMnemonic(share));
    }
    return mnemonicShares
  }
};

export default KeySplit;
