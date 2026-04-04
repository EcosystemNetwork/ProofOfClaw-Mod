import { Command } from "commander";
import chalk from "chalk";
import crypto from "node:crypto";
import {
  addOrg,
  loadOrgs,
  loadActiveState,
  setActiveOrg,
  findOrg,
  type OrgProfile,
} from "../lib/state.js";
import { getAddress } from "../lib/signer.js";
import { loadConfig } from "../lib/config.js";

export function registerOrgCommands(program: Command): void {
  const org = program
    .command("org")
    .description("Organization management commands");

  org
    .command("create <name>")
    .description("Create a new local org profile with auto-generated ENS name")
    .action(async (name: string) => {
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

        const sanitized = name.toLowerCase().replace(/[^a-z0-9-]/g, "-");
        const ensName = `${sanitized}.proofofclaw.eth`;

        const orgProfile: OrgProfile = {
          id: crypto.randomUUID(),
          name,
          ensName,
          createdAt: new Date().toISOString(),
          signerAddress,
        };

        addOrg(orgProfile);
        setActiveOrg(orgProfile.id);

        console.log(chalk.green.bold("\n  Organization created successfully!\n"));
        console.log(`  ${chalk.dim("ID:")}       ${orgProfile.id}`);
        console.log(`  ${chalk.dim("Name:")}     ${orgProfile.name}`);
        console.log(`  ${chalk.dim("ENS:")}      ${chalk.cyan(orgProfile.ensName)}`);
        console.log(`  ${chalk.dim("Signer:")}   ${orgProfile.signerAddress}`);
        console.log(`  ${chalk.dim("Created:")}  ${orgProfile.createdAt}`);
        console.log(
          chalk.dim("\n  Set as active organization.\n")
        );
      } catch (err) {
        console.error(
          chalk.red("Failed to create organization:"),
          err instanceof Error ? err.message : err
        );
        process.exit(1);
      }
    });

  org
    .command("list")
    .description("List all local org profiles")
    .action(() => {
      const orgs = loadOrgs();
      const active = loadActiveState();

      if (orgs.length === 0) {
        console.log(chalk.yellow("\n  No organizations found. Run `poc org create <name>` to create one.\n"));
        return;
      }

      console.log(chalk.bold("\n  Organizations\n"));
      for (const o of orgs) {
        const marker = o.id === active.activeOrgId ? chalk.green(" *") : "  ";
        console.log(
          `${marker} ${chalk.white.bold(o.name)} ${chalk.dim(`(${o.ensName})`)} ${chalk.dim(o.id.slice(0, 8))}`
        );
      }
      console.log(
        chalk.dim("\n  * = active organization\n")
      );
    });

  org
    .command("status")
    .description("Show the currently active organization")
    .action(() => {
      const active = loadActiveState();
      if (!active.activeOrgId) {
        console.log(chalk.yellow("\n  No active organization. Run `poc org create <name>` first.\n"));
        return;
      }

      const org = findOrg(active.activeOrgId);
      if (!org) {
        console.log(chalk.red("\n  Active org not found in state. State may be corrupted.\n"));
        return;
      }

      console.log(chalk.bold("\n  Active Organization\n"));
      console.log(`  ${chalk.dim("ID:")}       ${org.id}`);
      console.log(`  ${chalk.dim("Name:")}     ${chalk.white.bold(org.name)}`);
      console.log(`  ${chalk.dim("ENS:")}      ${chalk.cyan(org.ensName)}`);
      console.log(`  ${chalk.dim("Signer:")}   ${org.signerAddress}`);
      console.log(`  ${chalk.dim("Created:")}  ${org.createdAt}\n`);
    });
}
