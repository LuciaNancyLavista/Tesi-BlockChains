import hre from "hardhat";
import "@nomicfoundation/hardhat-toolbox-viem";
import { run } from "node:test";
import { spec } from "node:test/reporters";
import fs from "fs";
import path from "path";

async function main() {
    console.log("Running Solidity tests...");

    const files = fs.readdirSync("test").filter(f => f.endsWith(".ts"));
    for (const f of files) {
        await import("file://" + path.resolve("test", f).replace(/\\/g, '/'));
    }

    const stream = run();
    stream.compose(new spec()).pipe(process.stdout);
}
main().catch(console.error);
