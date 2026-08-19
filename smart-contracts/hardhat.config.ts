import { HardhatUserConfig } from "hardhat/config";
import toolbox from "@nomicfoundation/hardhat-toolbox-viem";

const config: HardhatUserConfig = {
  solidity: "0.8.24",
  plugins: [toolbox],
  test: {
    testRunner: "node"
  }
};

export default config;
