import Web3 from "web3";
import ProviderEngine from "web3-provider-engine";
import FixtureSubprovider from "web3-provider-engine/subproviders/fixture.js";
import FilterSubprovider from "web3-provider-engine/subproviders/filters.js";
import WalletSubprovider from "ethereumjs-wallet/provider-engine";
import Web3Subprovider from "web3-provider-engine/subproviders/web3.js";

import ShardStore from "../solidity/build/contracts/ShardStore.json";

import Wallet from "ethereumjs-wallet";
import BigNumber from "bignumber.js";

export class KeySplitContractInterface {
  constructor (options={}) {
    var rpcURL = options.rpcURL || "https://ropsten.infura.io/atjfYkLXBNdLI0zSm9eE"
    if(typeof window === 'undefined') {
      var window = {};
    }
    this.localStorage = options.localStorage || window.localStorage;
    if(options.currentProvider) {
      this.web3 = new Web3(options.currentProvider);
    } else if(window && window.web3) {
      this.web3 = new Web3(window.web3.currentProvider);
    } else {
      var privateKey = options.privateKey || localStorage.getItem("localPrivateKey");
      if(!privateKey) {
        privateKey = Wallet.generate().getPrivateKeyString().slice(2);
      }
      var wallet = Wallet.fromPrivateKey(new Buffer(privateKey, "hex"));
      this.engine = new ProviderEngine();
      this.web3 = new Web3(this.engine);
      // static results
      this.engine.addProvider(new FixtureSubprovider({
        web3_clientVersion: 'ProviderEngine/v0.0.0/javascript',
        net_listening: true,
        eth_hashrate: '0x00',
        eth_mining: false,
        eth_syncing: true,
      }))

      // filters
      this.engine.addProvider(new FilterSubprovider())

      // id mgmt
      this.engine.addProvider(new WalletSubprovider(wallet, {}))

      this.engine.addProvider(new Web3Subprovider(new Web3.providers.HttpProvider(rpcURL)));

      this.engine.on('block', function(block) {
        console.log('BLOCK CHANGED:', '#'+block.number.toString('hex'), '0x'+block.hash.toString('hex'))
      })

      // network connectivity error
      this.engine.on('error', function(err){
        // report connectivity errors
        console.error(err.stack)
      });

      // start polling for blocks
      this.engine.start()
    }
    this.contract = this.web3.eth.contract(ShardStore.abi).at(options.at || "0x8cdaf0cd259887258bc13a92c0a6da92698644c0");

    if(this.localStorage) {
      this.web3.eth.getAccounts((err, accounts) => {
        var shardList = JSON.parse(this.localStorage.getItem(`${accounts[0]}:shards`));
        for(var shard of shardList) {
          getStorageConfirmed(shard);
        }
      });
    }
  }

  stop() {
    if(this.engine) {
      this.engine.stop();
    }
  }

  deploy() {
    this.web3.eth.getAccounts((err, accounts) => {
      if(err) {
        console.log(err);
        return;
      }
      var defaultAccount = accounts[0];
      this.web3.eth.contract(ShardStore.abi).new({data: ShardStore.bytecode, gas: 1000000, from: defaultAccount}, (err, data) => {
        console.log(data);
      });
    })
  }

  confirmStorage(shardIds) {
    return new Promise((resolve, reject) => {
      this.web3.eth.getAccounts((err, accounts) => {
        if(err) { reject(err); return; }
        var defaultAccount = accounts[0];
        var shardNumbers = [];
        for(var shardId of shardIds){
          shardNumbers.push(new BigNumber(shardId, 16));
        }
        console.log(shardNumbers);
        this.contract.confirmStorage.estimateGas(shardNumbers, {from: defaultAccount}, (err, gas) => {
          this.contract.confirmStorage(shardNumbers, {from: defaultAccount, gas: gas}, (err, tx) => {
            if(err) {
              reject(err);
              return;
            }
            var confirmations = [];
            for(var shardId of shardIds) {
              confirmations.push(this.watchStorageConfirmed(shardId));
            }
            resolve(Promise.all(confirmations));
          });
        })
      });
    })
  }

  watchStorageConfirmed(shardId) {
    return new Promise((resolve, reject) => {
      var watcher = this.contract.StorageConfirmed({fromBlock: "latest", shardId: new BigNumber(shardId, 16)});
      watcher.watch((err, evt) => {
        if(err) {
          watcher.stopWatching(() => {});
          reject(err)
        }
        watcher.stopWatching(() => {});
        if(this.localStorage) {
          this.localStorage.setItem(`shard:${shardId}`, JSON.stringify({block: evt.blockNumber, trustedContact: evt.args.trustedContact}));
        }
        resolve({block: evt.blockNumber, trustedContact: evt.args.trustedContact});
      });
    });
  }

  getStorageConfirmed(shardId) {
    if(this.localStorage) {
      var shardData = JSON.parse(this.localStorage.getItem(`shard:${shardId}`));
    } else {
      var shardData = {block: 0};
    }
    return new Promise((resolve, reject) => {
      var watcher = this.contract.StorageConfirmed({fromBlock: shardData.block, shardId: new BigNumber(shardId, 16)});
      watcher.get((err, evts) => {
        if(err) {
          reject(err)
        }
        for(var evt of evts) {
          if(evt.blockNumber > shardData.block) {
            if(this.localStorage) {
              this.localStorage.setItem(`shard:${shardId}`, JSON.stringify({block: evt.blockNumber, trustedContact: evt.args.trustedContact}));
            }
            resolve({block: evt.blockNumber, trustedContact: evt.args.trustedContact});
          }
        }
      });
    });
  }
  getShardStatus() {
    return new Promise((resolve, reject) => {
      if(!this.localStorage) {
        resolve([]);
      }
      this.web3.eth.getAccounts((err, accounts) => {
        var shardIds = JSON.parse(this.localStorage.getItem(`${accounts[0]}:shards`));
        var shards = [];
        for(var shardId of shardIds) {
          var shard = JSON.parse(this.localStorage.getItem(`shard:${shardId}`));
          shard.update = this.watchStorageConfirmed(shardId);
        }
      });
    })
  }
  confirmStoredShards() {
    return new Promise((resolve, reject) => {
      if(!this.localStorage) {
        resolve([]);
      }
      var heldShards = JSON.parse(this.localStorage.getItem(`${this.account}:heldShards`));
      var currentShards = [];
      for(var shardId of heldShards) {
        if(this.localStorage.getItem(`encShard${shardId}`)) {
          currentShards.push(shardId);
        }
      }
      return confirmStorage(currentShards);
    });
  }



}
