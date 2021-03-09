const XSLDID = artifacts.require("XSLDID");
var AuthKey = new String("0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71");
var Serv = new String("0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b");

module.exports = function (deployer) {
  //const userAddress = accounts[3];
  ///deployer.deploy(Migrations);
  deployer.deploy(XSLDID, AuthKey.valueOf(),Serv.valueOf());
};
