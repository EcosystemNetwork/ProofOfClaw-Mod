import { Command } from "commander";
import chalk from "chalk";
import crypto from "node:crypto";
import {
  generateEpochBundle,
  generateEpochKey,
  type EpochBundle,
} from "../lib/epoch-bundle.js";
import { loadConfig } from "../lib/config.js";
import { getSigners } from "../lib/signer.js";
import { getSoulVaultSwarmContract } from "../lib/contracts.js";
import { loadActiveState, findSwarm } from "../lib/state.js";

export function registerEpochCommands(program: Command): void {
  const epoch = program
    .command("epoch")
    .description("Epoch key rotation and bundle management");

  epoch
    .command("rotate")
    .description(
      "Generate a new epoch bundle, wrap keys for all members, and call rotateEpoch on-chain"
    )
    .option("--dry-run", "Generate bundle locally without on-chain call")
    .option(
      "--members <json>",
      'JSON map of address->pubkey, e.g. \'{"0xABC":"04..."}\''
    )
    .action(
      async (opts: { dryRun?: boolean; members?: string }) => {
        try {
          const config = loadConfig();
          const active = loadActiveState();

          if (!active.activeSwarmId) {
            console.error(
              chalk.red(
                "No active swarm. Run `poc swarm create <name>` first."
              )
            );
            process.exit(1);
          }

          const swarm = findSwarm(active.activeSwarmId);
          if (!swarm) {
            console.error(chalk.red("Active swarm not found."));
            process.exit(1);
          }

          // Parse members
          let members: Record<string, string>;
          if (opts.members) {
            try {
              members = JSON.parse(opts.members);
            } catch {
              console.error(
                chalk.red("Invalid --members JSON. Expected: {\"0xAddr\": \"04pubkeyHex\"}")
              );
              process.exit(1);
            }
          } else {
            // Generate demo members for testing
            console.log(
              chalk.yellow(
                "  No --members provided. Generating demo epoch bundle with 2 test members.\n"
              )
            );
            const ec1 = crypto.createECDH("secp256k1");
            ec1.generateKeys();
            const ec2 = crypto.createECDH("secp256k1");
            ec2.generateKeys();
            members = {
              "0xDemo1111111111111111111111111111111111": ec1.getPublicKey(
                "hex",
                "uncompressed"
              ),
              "0xDemo2222222222222222222222222222222222": ec2.getPublicKey(
                "hex",
                "uncompressed"
              ),
            };
          }

          const memberCount = Object.keys(members).length;
          console.log(
            chalk.dim(`\n  Generating epoch bundle for ${memberCount} member(s)...`)
          );

          // Generate fresh epoch key
          const kEpoch = generateEpochKey();
          console.log(
            chalk.dim(`  Epoch key: ${kEpoch.toString("hex").slice(0, 16)}...`)
          );

          // Generate bundle
          const bundle = generateEpochBundle(members, kEpoch, Date.now());
          const bundleJson = JSON.stringify(bundle, null, 2);
          const bundleCid = `bafk${crypto.randomBytes(28).toString("hex")}`; // placeholder CID

          console.log(chalk.dim(`  Bundle CID: ${bundleCid}`));
          console.log(
            chalk.dim(
              `  Bundle size: ${Buffer.byteLength(bundleJson)} bytes`
            )
          );

          if (!opts.dryRun) {
            try {
              const { ogSigner } = getSigners(config);
              const contract = getSoulVaultSwarmContract(
                swarm.contractAddress,
                ogSigner
              );

              console.log(
                chalk.dim("  Calling rotateEpoch on-chain...")
              );
              const tx = await contract.rotateEpoch(bundleCid);
              console.log(chalk.dim(`  TX: ${tx.hash}`));
              const receipt = await tx.wait();

              console.log(
                chalk.green.bold("\n  Epoch rotated successfully!\n")
              );
              console.log(`  ${chalk.dim("TX Hash:")}    ${tx.hash}`);
              console.log(
                `  ${chalk.dim("Block:")}      ${receipt?.blockNumber ?? "pending"}`
              );
            } catch (err) {
              console.log(
                chalk.yellow(
                  `\n  On-chain call skipped: ${err instanceof Error ? err.message : "no signer or contract not deployed"}`
                )
              );
            }
          } else {
            console.log(
              chalk.dim("  Dry run: skipping on-chain rotateEpoch call.")
            );
          }

          console.log(
            chalk.green.bold("\n  Epoch bundle generated!\n")
          );
          console.log(`  ${chalk.dim("Nonce:")}     ${bundle.epochNonce}`);
          console.log(`  ${chalk.dim("Members:")}   ${memberCount}`);
          console.log(`  ${chalk.dim("CID:")}       ${chalk.cyan(bundleCid)}`);
          console.log(`  ${chalk.dim("Created:")}   ${bundle.createdAt}\n`);
        } catch (err) {
          console.error(
            chalk.red("Failed to rotate epoch:"),
            err instanceof Error ? err.message : err
          );
          process.exit(1);
        }
      }
    );

  epoch
    .command("show-bundle")
    .description("Show the latest epoch bundle info from the active swarm")
    .action(async () => {
      try {
        const config = loadConfig();
        const active = loadActiveState();

        if (!active.activeSwarmId) {
          console.error(
            chalk.red("No active swarm.")
          );
          process.exit(1);
        }

        const swarm = findSwarm(active.activeSwarmId);
        if (!swarm) {
          console.error(chalk.red("Active swarm not found."));
          process.exit(1);
        }

        console.log(
          chalk.dim(`\n  Querying latest epoch bundle from "${swarm.name}"...`)
        );

        try {
          const { ogSigner } = getSigners(config);
          const contract = getSoulVaultSwarmContract(
            swarm.contractAddress,
            ogSigner
          );

          const [bundleCid, epochNonce, memberCount] = await Promise.all([
            contract.latestEpochBundleCid(),
            contract.epochNonce(),
            contract.memberCount(),
          ]);

          console.log(chalk.bold("\n  Latest Epoch Bundle\n"));
          console.log(`  ${chalk.dim("Swarm:")}       ${swarm.name}`);
          console.log(`  ${chalk.dim("Contract:")}    ${swarm.contractAddress}`);
          console.log(
            `  ${chalk.dim("Epoch Nonce:")} ${epochNonce.toString()}`
          );
          console.log(
            `  ${chalk.dim("Members:")}     ${memberCount.toString()}`
          );
          console.log(
            `  ${chalk.dim("Bundle CID:")}  ${chalk.cyan(bundleCid || "(none)")}\n`
          );
        } catch (err) {
          console.log(
            chalk.yellow(
              `\n  Could not query on-chain: ${err instanceof Error ? err.message : "contract not available"}`
            )
          );
          console.log(
            chalk.dim(
              "  Ensure SOULVAULT_SWARM_CONTRACT is set and the contract is deployed.\n"
            )
          );
        }
      } catch (err) {
        console.error(
          chalk.red("Failed to show bundle:"),
          err instanceof Error ? err.message : err
        );
        process.exit(1);
      }
    });
}
