import chai from 'chai';
import KeySplit from '../src/KeySplit.js';
import bip39 from 'bip39';

const expect = chai.expect;

describe('KeySplit', () => {
  describe('KeySplit.mnemonicToSSS', () => {
    it('should create the number of shares specified for a 128 bit mnemonic', () => {
      for(var i = 0; i < 1000; i++) {
        var mnemonic = bip39.generateMnemonic();
        var shares = KeySplit.mnemonicToSSS(mnemonic, 3, 2, "foo");
        expect(shares).to.have.lengthOf(3);
        for(var share of shares) {
          expect(share.split(" ")).to.have.lengthOf(27);
        }
      }
    });
    it('should create the number of shares specified for a 256 bit mnemonic', () => {
      for(var i = 0; i < 1000; i++) {
        var mnemonic = bip39.generateMnemonic(256);
        var shares = KeySplit.mnemonicToSSS(mnemonic, 3, 2, "foo");
        expect(shares).to.have.lengthOf(3);
        for(var share of shares) {
          expect(share.split(" ")).to.have.lengthOf(39);
        }
      }
    });
  });
  describe('KeySplit.combineSSS', () => {
    it('should create the number of shares specified for a 128 bit mnemonic', () => {
      for(var i = 0; i < 100; i++) {
        var mnemonic = bip39.generateMnemonic();
        var shares = KeySplit.mnemonicToSSS(mnemonic, 3, 2, "foo");
        for(var j = 0; j < 3; j++) {
          for(var k = 0; k < 3; k++) {
            if(j == k) { continue }
            expect(KeySplit.combineSSS([shares[j], shares[k]], "foo")).to.equal(mnemonic);
          }
        }
      }
    });
    it('should create the number of shares specified for a 256 bit mnemonic', () => {
      for(var i = 0; i < 100; i++) {
        var mnemonic = bip39.generateMnemonic(256);
        var shares = KeySplit.mnemonicToSSS(mnemonic, 3, 2, "foo");
        for(var j = 0; j < 3; j++) {
          for(var k = 0; k < 3; k++) {
            if(j == k) { continue }
            expect(KeySplit.combineSSS([shares[j], shares[k]], "foo")).to.equal(mnemonic);
          }
        }
      }
    });
  });
});
