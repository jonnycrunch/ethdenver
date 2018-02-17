import _getIterator from 'babel-runtime/core-js/get-iterator';
import secrets from 'secrets.js-next';
import bip39 from 'bip39';

function repeat(char, number) {
  var string = "";
  for (var i = 0; i < number; i++) {
    string += char;
  }
  return string;
}

var KeySplit = {
  mnemonicToSSS: function mnemonicToSSS(mnemonic, shareCount, threshold) {
    var key = bip39.mnemonicToEntropy(mnemonic);
    var shares = secrets.share(key, shareCount, threshold);
    console.log(shares);
    var mnemonicShares = [];
    var _iteratorNormalCompletion = true;
    var _didIteratorError = false;
    var _iteratorError = undefined;

    try {
      for (var _iterator = _getIterator(shares), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
        var share = _step.value;

        share += repeat("0", 8 - share.length % 8);
        console.log(share);
        mnemonicShares.push(bip39.entropyToMnemonic(share));
      }
    } catch (err) {
      _didIteratorError = true;
      _iteratorError = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion && _iterator.return) {
          _iterator.return();
        }
      } finally {
        if (_didIteratorError) {
          throw _iteratorError;
        }
      }
    }

    return mnemonicShares;
  }
};

export { KeySplit };
//# sourceMappingURL=index.es.js.map
