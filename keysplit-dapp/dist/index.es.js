import _slicedToArray from 'babel-runtime/helpers/slicedToArray';
import _getIterator from 'babel-runtime/core-js/get-iterator';
import _Promise from 'babel-runtime/core-js/promise';
import _classCallCheck from 'babel-runtime/helpers/classCallCheck';
import _createClass from 'babel-runtime/helpers/createClass';
import secrets from 'secrets.js-next';
import bip39 from 'bip39';
import createHash from 'create-hash';
import unorm from 'unorm';
import crypto from 'crypto';
import rp from 'request-promise-native';

/*
 * This module does bip39-like encoding of byte strings to words. It removes
 * the constraint from the original bip39 module to ensure that the encoded
 * bytes are 128 < x < 256 bits. We still want to use bip39 for encoding and
 * decoding actual keys, but when it comes to encoding the Shamir's Secret
 * Sharing shards we want a human-readable encoding that can exceed 256 bits
 * and may not be divisible by 4.
 */

var INVALID_ENTROPY = 'Invalid entropy';
var INVALID_MNEMONIC = 'Invalid mnemonic';
var INVALID_CHECKSUM = 'Invalid mnemonic checksum';

function bytesToBinary(bytes) {
  return bytes.map(function (x) {
    return lpad(x.toString(2), '0', 8);
  }).join('');
}

function binaryToByte(bin) {
  return parseInt(bin, 2);
}

function lpad(str, padString, length) {
  while (str.length < length) {
    str = padString + str;
  }return str;
}

function deriveChecksumBits(entropyBuffer) {
  var ENT = entropyBuffer.length * 8;
  var CS = ENT / 32;
  var hash = createHash('sha256').update(entropyBuffer).digest();

  return bytesToBinary([].slice.call(hash)).slice(0, CS);
}

function entropyToMnemonic(entropy, wordlist) {
  if (!Buffer.isBuffer(entropy)) entropy = Buffer.from(entropy, 'hex');
  wordlist = wordlist || bip39.wordlists.EN;

  if (entropy.length % 4 !== 0) throw new TypeError(INVALID_ENTROPY);

  var entropyBits = bytesToBinary([].slice.call(entropy));
  var checksumBits = deriveChecksumBits(entropy);

  var bits = entropyBits + checksumBits;
  var chunks = bits.match(/(.{1,11})/g);
  var words = chunks.map(function (binary) {
    var index = binaryToByte(binary);
    return wordlist[index];
  });

  return wordlist === bip39.wordlists.JA ? words.join('\u3000') : words.join(' ');
}

function mnemonicToEntropy(mnemonic, wordlist) {
  wordlist = wordlist || bip39.wordlists.EN;

  var words = unorm.nfkd(mnemonic).split(' ');
  // if (words.length % 3 !== 0) throw new Error(INVALID_MNEMONIC)

  // convert word indices to 11 bit binary strings
  var bits = words.map(function (word) {
    var index = wordlist.indexOf(word);
    if (index === -1) throw new Error(INVALID_MNEMONIC);

    return lpad(index.toString(2), '0', 11);
  }).join('');

  // split the binary string into ENT/CS
  var dividerIndex = Math.floor(bits.length / 33) * 32;
  var entropyBits = bits.slice(0, dividerIndex);
  var checksumBits = bits.slice(dividerIndex);

  // calculate the checksum and compare
  var entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte);

  var entropy = Buffer.from(entropyBytes);
  var newChecksum = deriveChecksumBits(entropy);
  if (newChecksum !== checksumBits) throw new Error(INVALID_CHECKSUM);

  return entropy.toString('hex');
}

var ApiEndpoint = function () {
  function ApiEndpoint(apiServer) {
    _classCallCheck(this, ApiEndpoint);

    this.apiServer = apiServer;
  }

  _createClass(ApiEndpoint, [{
    key: 'upload',
    value: function upload(body) {
      return rp({
        method: 'POST',
        uri: apiServer,
        body: body,
        json: true
      });
    }
  }, {
    key: 'download',
    value: function download(shardid) {
      return rp({
        method: 'GET',
        uri: this.apiServer + '?id=' + shardid,
        json: true
      });
    }
  }]);

  return ApiEndpoint;
}();

var passwordStore = {};

var KeySplit = function () {
  function KeySplit(password, apiUrl) {
    _classCallCheck(this, KeySplit);

    this.apiUrl = apiUrl || "https://cgr6zthug7.execute-api.us-east-2.amazonaws.com/keysplit";
    passwordStore[this] = password;
  }

  _createClass(KeySplit, [{
    key: 'mnemonicToSSS',
    value: function mnemonicToSSS(mnemonic, shareCount, threshold, password) {
      password = password || passwordStore[this];
      var key = bip39.mnemonicToEntropy(mnemonic);
      var salt = crypto.randomBytes(8);
      return new _Promise(function (resolve, reject) {
        return crypto.pbkdf2(password, salt, 100000, 16, 'sha512', function (err, pbkdf2Pass) {
          if (err) {
            reject(err);
          }
          var c = crypto.createCipher("aes128", pbkdf2Pass);
          var encKey = c.update(key, 'hex', 'hex');
          encKey += c.final('hex');
          var splitVal = salt.toString("hex") + encKey;
          var shares = secrets.share(splitVal, shareCount, threshold);
          var mnemonicShares = [];
          var _iteratorNormalCompletion = true;
          var _didIteratorError = false;
          var _iteratorError = undefined;

          try {
            for (var _iterator = _getIterator(shares), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
              var share = _step.value;

              mnemonicShares.push(entropyToMnemonic(share + "000"));
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

          resolve(mnemonicShares);
        });
      });
    }
  }, {
    key: 'combineSSS',
    value: function combineSSS(mnemonicShares, password) {
      password = password || passwordStore[this];
      var shares = [];
      var _iteratorNormalCompletion2 = true;
      var _didIteratorError2 = false;
      var _iteratorError2 = undefined;

      try {
        for (var _iterator2 = _getIterator(mnemonicShares), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
          var share = _step2.value;

          var shareHex = mnemonicToEntropy(share);
          shares.push(shareHex.slice(0, shareHex.length - 3));
        }
      } catch (err) {
        _didIteratorError2 = true;
        _iteratorError2 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion2 && _iterator2.return) {
            _iterator2.return();
          }
        } finally {
          if (_didIteratorError2) {
            throw _iteratorError2;
          }
        }
      }

      var splitVal = secrets.combine(shares);
      var salt = new Buffer(splitVal.slice(0, 16), "hex");
      var encKey = splitVal.slice(16);
      return new _Promise(function (resolve, reject) {
        return crypto.pbkdf2(password, salt, 100000, 16, 'sha512', function (err, pbkdf2Pass) {
          if (err) {
            reject(err);
          }
          var d = crypto.createDecipher("aes128", pbkdf2Pass);
          var rawKey = d.update(encKey, "hex", "hex");
          rawKey += d.final("hex");
          return bip39.entropyToMnemonic(rawKey);
        });
      });
    }
  }, {
    key: 'uploadShard',
    value: function uploadShard(shard, uploader) {
      uploader = uploader || new ApiEndpoint(this.apiUrl);
      var hash = crypto.createHash('sha256');
      var shardHex = mnemonicToEntropy(shard);
      hash.update(shardHex, "hex");
      var result = {
        shardid: hash.digest(),
        key: crypto.randomBytes(32)
      };
      var c = crypto.createCipher("aes256", result.key);
      var encShard = c.update(shardHex, "hex", "base64");
      encShard += c.final("base64");
      return uploader.upload({ shardid: result.shardid, data: encShard }).then(function (response) {
        result.objectid = response;
        return result;
      });
    }
  }, {
    key: 'downloadShard',
    value: function downloadShard(pathAndKey, downloader) {
      downloader = downloader || new ApiEndpoint(this.apiUrl);
      var objectid, key;

      var _pathAndKey$split = pathAndKey.split(":");

      var _pathAndKey$split2 = _slicedToArray(_pathAndKey$split, 2);

      objectid = _pathAndKey$split2[0];
      key = _pathAndKey$split2[1];

      return downloader.download(objectid).then(function (response) {
        console.log(objectid, key);
        var d = crypto.createDecipher("aes256", new Buffer(key, "base64"));
        var shardHex = d.update(response.data, "base64", "hex");
        shardHex += d.final("hex");
        return entropyToMnemonic(shardHex);
      });
    }
  }, {
    key: 'saveShard',
    value: function saveShard(shard, password) {
      password = password || passwordStore[this];
      var salt = crypto.randomBytes(8);
      var pbkdf2Pass = crypto.pbkdf2Sync(password, salt, 100000, 16, 'sha512');
      var c = crypto.createCipher("aes128", pbkdf2Pass);
      var encKey = c.update(key, 'hex', 'hex');
      encKey += c.final('hex');
    }
  }]);

  return KeySplit;
}();

export { KeySplit };
//# sourceMappingURL=index.es.js.map
