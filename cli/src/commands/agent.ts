import { Command } from "commander";
import chalk from "chalk";
import crypto from "node:crypto";
import {
  addAgent,
  loadAgents,
  findAgent,
  updateAgent,
  type AgentProfile,
} from "../lib/state.js";
import { loadConfig } from "../lib/config.js";
import { getSigners, getAddress } from "../lib/signer.js";
import { getERC8004RegistryContract } from "../lib/contracts.js";

export function registerAgentCommands(program: Command): void {
  const agent = program
    .command("agent")
    .description("Agent identity and registration commands");

  agent
    .command("create <name>")
    .description("Create a new agent profile from the configured signer")
    .option("--uri <uri>", "Agent metadata URI", "")
    .action(async (name: string, opts: { uri: string }) => {
      try {
        const config = loadConfig();
        let signerAddress: string;
        try {
          signerAddress = getAddress(config);
        } catch {
          signerAddress = "0x" + crypto.randomBytes(20).toString("hex");
          console.log(
            chalk.yellow(
              "No signer configured. Using generated placeholder address."
            )
          );
        }

        const agentProfile: AgentProfile = {
          id: crypto.randomUUID(),
          name,
          signerAddress,
          registeredOnChain: false,
          uri: opts.uri || undefined,
          createdAt: new Date().toISOString(),
        };

        addAgent(agentProfile);

        console.log(chalk.green.bold("\n  Agent profile created!\n"));
        console.log(`  ${chalk.dim("ID:")}       ${agentProfile.id}`);
        console.log(`  ${chalk.dim("Name:")}     ${chalk.white.bold(agentProfile.name)}`);
        console.log(`  ${chalk.dim("Signer:")}   ${agentProfile.signerAddress}`);
        console.log(
          `  ${chalk.dim("On-chain:")} ${chalk.yellow("not registered")}`
        );
        if (agentProfile.uri) {
          console.log(`  ${chalk.dim("URI:")}      ${agentProfile.uri}`);
        }
        console.log(
          chalk.dim(
            "\n  Run `poc agent register` to register on-chain via ERC-8004.\n"
          )
        );
      } catch (err) {
        console.error(
          chalk.red("Failed to create agent:"),
          err instanceof Error ? err.message : err
        );
        process.exit(1);
      }
    });

  agent
    .command("register")
    .description("Register the latest agent on-chain via ERC-8004")
    .option("--agent-id <id>", "Specific agent ID to register")
    .option(
      "--uri <uri>",
      "Metadata URI for the agent",
      "ipfs://placeholder"
    )
    .action(async (opts: { agentId?: string; uri: string }) => {
      try {
        const config = loadConfig();
        const agents = loadAgents();

        if (agents.length === 0) {
          console.error(
            chalk.red(
              "No agents found. Run `poc agent create <name>` first."
            )
          );
          process.exit(1);
        }

        const agent = opts.agentId
          ? findAgent(opts.agentId)
          : agents[agents.length - 1];

        if (!agent) {
          console.error(chalk.red("Agent not found."));
          process.exit(1);
        }

        if (agent.registeredOnChain) {
          console.log(
            chalk.yellow(
              `\n  Agent "${agent.name}" is already registered on-chain (tokenId: ${agent.tokenId}).\n`
            )
          );
          return;
        }

        const { sepoliaSigner } = getSigners(config);
        const address = await sepoliaSigner.getAddress();

        console.log(chalk.dim(`\n  Registering agent "${agent.name}" on-chain...`));
        console.log(chalk.dim(`  Signer: ${address}`));
        console.log(
          chalk.dim(`  Registry: ${config.ERC8004_REGISTRY_ADDRESS}`)
        );

        const contract = getERC8004RegistryContract(
          config.ERC8004_REGISTRY_ADDRESS,
          sepoliaSigner
        );

        const tx = await contract.registerAgent(address, opts.uri);
        console.log(chalk.dim(`  TX: ${tx.hash}`));
        const receipt = await tx.wait();

        // Try to extract tokenId from event logs
        let tokenId = "unknown";
        if (receipt?.logs) {
          for (const log of receipt.logs) {
            try {
              const parsed = contract.interface.parseLog({
                topics: log.topics as string[],
                data: log.data,
              });
              if (parsed?.name === "AgentRegistered") {
                tokenId = parsed.args.tokenId.toString();
              }
            } catch {
              // Not our event
            }
          }
        }

        updateAgent(agent.id, {
          registeredOnChain: true,
          tokenId,
          uri: opts.uri,
        });

        console.log(chalk.green.bold("\n  Agent registered on-chain!\n"));
        console.log(`  ${chalk.dim("Name:")}     ${agent.name}`);
        console.log(`  ${chalk.dim("Token ID:")} ${chalk.cyan(tokenId)}`);
        console.log(`  ${chalk.dim("URI:")}      ${opts.uri}`);
        console.log(`  ${chalk.dim("TX Hash:")}  ${tx.hash}\n`);
      } catch (err) {
        console.error(
          chalk.red("Failed to register agent:"),
          err instanceof Error ? err.message : err
        );
        process.exit(1);
      }
    });

  agent
    .command("status")
    .description("Show agent profiles and their registration status")
    .option("--agent-id <id>", "Show a specific agent")
    .action((opts: { agentId?: string }) => {
      const agents = loadAgents();

      if (agents.length === 0) {
        console.log(
          chalk.yellow(
            "\n  No agents found. Run `poc agent create <name>` to create one.\n"
          )
        );
        return;
      }

      const list = opts.agentId
        ? agents.filter((a) => a.id === opts.agentId)
        : agents;

      if (list.length === 0) {
        console.log(chalk.yellow("\n  Agent not found.\n"));
        return;
      }

      console.log(chalk.bold("\n  Agent Profiles\n"));
      for (const a of list) {
        const status = a.registeredOnChain
          ? chalk.green("registered")
          : chalk.yellow("local only");

        console.log(`  ${chalk.white.bold(a.name)} ${chalk.dim(`(${a.id.slice(0, 8)})`)}`);
        console.log(`    ${chalk.dim("Signer:")}   ${a.signerAddress}`);
        console.log(`    ${chalk.dim("Status:")}   ${status}`);
        if (a.tokenId) {
          console.log(`    ${chalk.dim("Token ID:")} ${a.tokenId}`);
        }
        if (a.uri) {
          console.log(`    ${chalk.dim("URI:")}      ${a.uri}`);
        }
        console.log(`    ${chalk.dim("Created:")}  ${a.createdAt}`);
        console.log();
      }
    });
}
