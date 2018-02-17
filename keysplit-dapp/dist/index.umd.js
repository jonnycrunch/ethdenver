(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('babel-runtime/core-js/get-iterator'), require('secrets.js-next'), require('bip39')) :
  typeof define === 'function' && define.amd ? define(['exports', 'babel-runtime/core-js/get-iterator', 'secrets.js-next', 'bip39'], factory) :
  (factory((global.KeySplit = global.KeySplit || {}, global.KeySplit.js = global.KeySplit.js || {}),global._getIterator,global.secrets,global.bip39));
}(this, (function (exports,_getIterator,secrets,bip39) { 'use strict';

_getIterator = 'default' in _getIterator ? _getIterator['default'] : _getIterator;
secrets = 'default' in secrets ? secrets['default'] : secrets;
bip39 = 'default' in bip39 ? bip39['default'] : bip39;

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

Object.defineProperty(exports, '__esModule', { value: true });

})));
//# sourceMappingURL=index.umd.js.map
