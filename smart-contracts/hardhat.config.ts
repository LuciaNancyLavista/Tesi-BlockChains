import { HardhatUserConfig } from "hardhat/config";
import toolbox from "@nomicfoundation/hardhat-toolbox-viem";
import * as dotenv from "dotenv";

dotenv.config();

const config: HardhatUserConfig = {
  solidity: "0.8.24",
  plugins: [toolbox],
  networks: {
    sepolia: {
      type: "http",
      url: process.env.SEPOLIA_URL || "",
      accounts: process.env.PRIVATE_KEY ? [(process.env.PRIVATE_KEY.startsWith('0x') ? '' : '0x') + process.env.PRIVATE_KEY] : [],
    }
  },
  test: {
    testRunner: "node"
  }
};

export default config;
