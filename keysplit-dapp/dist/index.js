'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var _getIterator = _interopDefault(require('babel-runtime/core-js/get-iterator'));
var secrets = _interopDefault(require('secrets.js-next'));
var bip39 = _interopDefault(require('bip39'));

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

exports.KeySplit = KeySplit;
//# sourceMappingURL=index.js.map
