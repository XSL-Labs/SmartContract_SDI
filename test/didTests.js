var assert = require("assert")
const crypto = require("crypto");
const web3 = require("web3");
//const { accounts, contract, defaultSender, web3 } = require('test-environment');
//const { BN, constants, expectEvent, expectRevert, time, balance, send } = require('@openzeppelin/test-helpers');


const XSLDIDClass = artifacts.require("XSLDID");

contract('XSLDIDClass', (accounts) => {
  let instance;
  beforeEach('should setup the contract instance', async () => {
     instance = await XSLDIDClass.deployed();
    });

  it("should return the owner", async ()=> {
    const value = await instance.owner();
    assert.equal(value, accounts[0]);
  });
  it("Creat DID for User1 by Admin", async ()=> {
    const auth = "0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71";
    const serv = "0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b";
    await instance.creatDID(accounts[1],serv, auth);
    const value = await instance.getDID(accounts[1]);
    assert.equal(value[0], accounts[1]);
    assert.equal(value[1], serv);
    assert.equal(value[2], auth);
  });

  it("Creat DID for Issuer1 by admin", async ()=> {
    const auth = "0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71";
    const serv = "0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b";
    await instance.creatDIDForIssuer(accounts[2],serv, auth);
    const value = await instance.getDID(accounts[2]);
    assert.equal(value[0], accounts[2]);
    assert.equal(value[1], serv);
    assert.equal(value[2], auth);
  });

  it("Creat DID for User2 by Issuer1 ", async ()=> {
    const auth = "0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71";
    const serv = "0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b";
    await instance.creatDID(accounts[3],serv, auth, {from: accounts[2]});
    const value = await instance.getDID(accounts[3]);
    assert.equal(value[0], accounts[3]);
    assert.equal(value[1], serv);
    assert.equal(value[2], auth);
  });

  it("Add VC for User1", async ()=> {
    const VC = "0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b";
    await instance.addVC( VC, accounts[2]);
    const  timpstemp  =  await instance.getVCtimestamp( VC,accounts[2]);
    console.log(timpstemp);
  });

  it("Add attribut to User1 DID document ", async ()=> {
    const name     = "0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b";
    const validity = "0x02";
    const value    = "0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71";

    await instance.setAttribute(accounts[1],name,  validity, value, {from: accounts[1]});
    const result = await instance.changed[accounts[1]];
    console.log(result);
  });
});
