import chai from 'chai';
import KeySplit from '../src/KeySplit.js';
import bip39 from 'bip39';
import uuidv4 from 'uuid/v4';

const expect = chai.expect;

class MockApiEndpoint {
  constructor () {
    this.items = {};
  }
  upload(data) {
    return new Promise((resolve, reject) => {
      var id = uuidv4();
      this.items[id] = data;
      resolve(id);
    })
  }
  download(id) {
    return new Promise((resolve, reject) => {
      if(!this.items[id]) {
        reject("not found");
      }
      resolve(this.items[id]);
    });
  }
}

describe('KeySplit', () => {
  describe('KeySplit.mnemonicToSSS', () => {
    it('should create the number of shares specified for a 128 bit mnemonic', () => {
      for(var i = 0; i < 10; i++) {
        var mnemonic = bip39.generateMnemonic();
        var shares = KeySplit.mnemonicToSSS(mnemonic, 3, 2, "foo");
        expect(shares).to.have.lengthOf(3);
        for(var share of shares) {
          expect(share.split(" ")).to.have.lengthOf(33);
        }
      }
    }).timeout(10000);
    it('should create the number of shares specified for a 256 bit mnemonic', () => {
      for(var i = 0; i < 10; i++) {
        var mnemonic = bip39.generateMnemonic(256);
        var shares = KeySplit.mnemonicToSSS(mnemonic, 3, 2, "foo");
        expect(shares).to.have.lengthOf(3);
        for(var share of shares) {
          expect(share.split(" ")).to.have.lengthOf(45);
        }
      }
    }).timeout(10000);
  });
  describe('KeySplit.combineSSS', () => {
    it('should create the number of shares specified for a 128 bit mnemonic', () => {
      for(var i = 0; i < 10; i++) {
        var mnemonic = bip39.generateMnemonic();
        var shares = KeySplit.mnemonicToSSS(mnemonic, 3, 2, "foo");
        for(var j = 0; j < 3; j++) {
          for(var k = 0; k < 3; k++) {
            if(j == k) { continue }
            expect(KeySplit.combineSSS([shares[j], shares[k]], "foo")).to.equal(mnemonic);
          }
        }
      }
    }).timeout(20000);
    it('should create the number of shares specified for a 256 bit mnemonic', () => {
      for(var i = 0; i < 10; i++) {
        var mnemonic = bip39.generateMnemonic(256);
        var shares = KeySplit.mnemonicToSSS(mnemonic, 3, 2, "foo");
        for(var j = 0; j < 3; j++) {
          for(var k = 0; k < 3; k++) {
            if(j == k) { continue }
            expect(KeySplit.combineSSS([shares[j], shares[k]], "foo")).to.equal(mnemonic);
          }
        }
      }
    }).timeout(20000);
  });
  describe('KeySplit.uploadShard', () => {
    it('should upload a shard', () => {
      var mnemonic = bip39.generateMnemonic();
      var shares = KeySplit.mnemonicToSSS(mnemonic, 3, 2, "foo");
      var mockEndpoint = new MockApiEndpoint();
      return KeySplit.uploadShard(shares[0], mockEndpoint).then((result) => {
        expect(result.key).to.have.lengthOf(32);
        expect(result.shardid).to.have.lengthOf(32);
        expect(mockEndpoint.items[result.objectid]).to.not.have.keys("key");
        expect(mockEndpoint.items[result.objectid]).to.have.all.keys("data", "shardid");
      })
    })
  });
});
