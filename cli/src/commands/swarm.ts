import { Command } from "commander";
import chalk from "chalk";
import crypto from "node:crypto";
import {
  addSwarm,
  loadSwarms,
  loadActiveState,
  setActiveSwarm,
  findSwarm,
} from "../lib/state.js";
import { loadConfig } from "../lib/config.js";
import { getSigners } from "../lib/signer.js";
import { getSoulVaultSwarmContract } from "../lib/contracts.js";

export function registerSwarmCommands(program: Command): void {
  const swarm = program
    .command("swarm")
    .description("Swarm management commands");

  swarm
    .command("create <name>")
    .description(
      "Create a swarm profile and deploy SoulVaultSwarm contract on 0G"
    )
    .option("--dry-run", "Skip on-chain deployment, create local profile only")
    .action(async (name: string, opts: { dryRun?: boolean }) => {
      try {
        const config = loadConfig();
        const active = loadActiveState();

        if (!active.activeOrgId) {
          console.error(
            chalk.red(
              "No active organization. Run `poc org create <name>` first."
            )
          );
          process.exit(1);
        }

        let contractAddress = "0x" + "0".repeat(40);
        let chainId = config.OG_CHAIN_ID;

        if (!opts.dryRun) {
          console.log(chalk.dim("  Deploying SoulVaultSwarm contract to 0G..."));
          try {
            const { ogSigner } = getSigners(config);
            // In production, this would deploy the contract.
            // For now, we record the configured contract address.
            contractAddress = config.SOULVAULT_SWARM_CONTRACT;
            chainId = config.OG_CHAIN_ID;
            const address = await ogSigner.getAddress();
            console.log(
              chalk.dim(`  Signer: ${address}`)
            );
            console.log(
              chalk.yellow(
                "  Note: Using configured SOULVAULT_SWARM_CONTRACT address. Full deployment coming soon."
              )
            );
          } catch (err) {
            console.log(
              chalk.yellow(
                `  Skipping on-chain deploy: ${err instanceof Error ? err.message : "no signer configured"}`
              )
            );
          }
        } else {
          console.log(chalk.dim("  Dry run: skipping on-chain deployment."));
        }

        const swarmProfile = {
          id: crypto.randomUUID(),
          name,
          orgId: active.activeOrgId,
          contractAddress,
          chainId,
          createdAt: new Date().toISOString(),
          members: [] as string[],
        };

        addSwarm(swarmProfile);
        setActiveSwarm(swarmProfile.id);

        console.log(chalk.green.bold("\n  Swarm created successfully!\n"));
        console.log(`  ${chalk.dim("ID:")}        ${swarmProfile.id}`);
        console.log(`  ${chalk.dim("Name:")}      ${swarmProfile.name}`);
        console.log(`  ${chalk.dim("Org:")}       ${swarmProfile.orgId.slice(0, 8)}`);
        console.log(
          `  ${chalk.dim("Contract:")}  ${chalk.cyan(swarmProfile.contractAddress)}`
        );
        console.log(`  ${chalk.dim("Chain:")}     ${swarmProfile.chainId}`);
        console.log(chalk.dim("\n  Set as active swarm.\n"));
      } catch (err) {
        console.error(
          chalk.red("Failed to create swarm:"),
          err instanceof Error ? err.message : err
        );
        process.exit(1);
      }
    });

  swarm
    .command("list")
    .description("List all local swarm profiles")
    .action(() => {
      const swarms = loadSwarms();
      const active = loadActiveState();

      if (swarms.length === 0) {
        console.log(
          chalk.yellow(
            "\n  No swarms found. Run `poc swarm create <name>` to create one.\n"
          )
        );
        return;
      }

      console.log(chalk.bold("\n  Swarms\n"));
      for (const s of swarms) {
        const marker =
          s.id === active.activeSwarmId ? chalk.green(" *") : "  ";
        console.log(
          `${marker} ${chalk.white.bold(s.name)} ${chalk.dim(`(${s.members.length} members)`)} ${chalk.dim(s.id.slice(0, 8))}`
        );
      }
      console.log(chalk.dim("\n  * = active swarm\n"));
    });

  swarm
    .command("join-request")
    .description("Submit a join request to the active swarm")
    .action(async () => {
      try {
        const config = loadConfig();
        const active = loadActiveState();

        if (!active.activeSwarmId) {
          console.error(
            chalk.red("No active swarm. Run `poc swarm create <name>` first.")
          );
          process.exit(1);
        }

        const swarm = findSwarm(active.activeSwarmId);
        if (!swarm) {
          console.error(chalk.red("Active swarm not found in state."));
          process.exit(1);
        }

        const { ogSigner } = getSigners(config);
        const address = await ogSigner.getAddress();

        console.log(chalk.dim(`\n  Submitting join request to swarm "${swarm.name}"...`));
        console.log(chalk.dim(`  Signer: ${address}`));
        console.log(chalk.dim(`  Contract: ${swarm.contractAddress}`));

        const contract = getSoulVaultSwarmContract(
          swarm.contractAddress,
          ogSigner
        );

        // Generate a public key from the signer for the join request
        const pubkey = "0x04" + crypto.randomBytes(64).toString("hex"); // placeholder
        console.log(chalk.dim(`  Pubkey: ${pubkey.slice(0, 20)}...`));

        const tx = await contract.requestJoin(pubkey);
        console.log(chalk.dim(`  TX: ${tx.hash}`));
        const receipt = await tx.wait();

        console.log(
          chalk.green.bold("\n  Join request submitted successfully!\n")
        );
        console.log(`  ${chalk.dim("TX Hash:")} ${tx.hash}`);
        console.log(
          `  ${chalk.dim("Block:")}   ${receipt?.blockNumber ?? "pending"}\n`
        );
      } catch (err) {
        console.error(
          chalk.red("Failed to submit join request:"),
          err instanceof Error ? err.message : err
        );
        process.exit(1);
      }
    });

  swarm
    .command("approve-join <requestId>")
    .description("Approve a pending join request")
    .action(async (requestId: string) => {
      try {
        const config = loadConfig();
        const active = loadActiveState();

        if (!active.activeSwarmId) {
          console.error(chalk.red("No active swarm."));
          process.exit(1);
        }

        const swarm = findSwarm(active.activeSwarmId);
        if (!swarm) {
          console.error(chalk.red("Active swarm not found in state."));
          process.exit(1);
        }

        const { ogSigner } = getSigners(config);
        const contract = getSoulVaultSwarmContract(
          swarm.contractAddress,
          ogSigner
        );

        console.log(
          chalk.dim(`\n  Approving join request #${requestId}...`)
        );

        const tx = await contract.approveJoin(BigInt(requestId));
        console.log(chalk.dim(`  TX: ${tx.hash}`));
        const receipt = await tx.wait();

        console.log(
          chalk.green.bold("\n  Join request approved!\n")
        );
        console.log(`  ${chalk.dim("Request:")} #${requestId}`);
        console.log(`  ${chalk.dim("TX Hash:")} ${tx.hash}`);
        console.log(
          `  ${chalk.dim("Block:")}   ${receipt?.blockNumber ?? "pending"}\n`
        );
      } catch (err) {
        console.error(
          chalk.red("Failed to approve join request:"),
          err instanceof Error ? err.message : err
        );
        process.exit(1);
      }
    });
}
