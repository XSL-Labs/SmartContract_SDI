
const DIDs = artifacts.require("./XSLDID.sol");

module.exports = function(deployer) {
  deployer.deploy(DIDs);

};
