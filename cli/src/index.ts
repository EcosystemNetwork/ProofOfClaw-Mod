#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import { registerOrgCommands } from "./commands/organization.js";
import { registerSwarmCommands } from "./commands/swarm.js";
import { registerAgentCommands } from "./commands/agent.js";
import { registerEpochCommands } from "./commands/epoch.js";
import { registerBackupCommands } from "./commands/backup.js";

const program = new Command();

program
  .name("poc")
  .description(
    chalk.bold("Proof of Claw CLI") +
      " — programmatic access to org, swarm, agent, and epoch operations"
  )
  .version("0.1.0");

// Register all command groups
registerOrgCommands(program);
registerSwarmCommands(program);
registerAgentCommands(program);
registerEpochCommands(program);
registerBackupCommands(program);

// Global error handling
program.exitOverride();

try {
  await program.parseAsync(process.argv);
} catch (err: unknown) {
  if (
    err instanceof Error &&
    "code" in err &&
    (err as { code: string }).code === "commander.helpDisplayed"
  ) {
    // Help was shown, exit gracefully
    process.exit(0);
  }
  if (
    err instanceof Error &&
    "code" in err &&
    (err as { code: string }).code === "commander.version"
  ) {
    process.exit(0);
  }
  // Other commander errors (e.g., missing args) are already printed
  if (
    err instanceof Error &&
    "code" in err &&
    typeof (err as { code: string }).code === "string" &&
    (err as { code: string }).code.startsWith("commander.")
  ) {
    process.exit(1);
  }
  console.error(chalk.red("Unexpected error:"), err);
  process.exit(1);
}
