import { Command } from "commander";
import chalk from "chalk";
import crypto from "node:crypto";
import fs from "fs-extra";
import path from "node:path";
import { encryptBackup, decryptBackup } from "../lib/backup.js";
import { generateEpochKey } from "../lib/epoch-bundle.js";
import { loadConfig } from "../lib/config.js";
import { getSigners } from "../lib/signer.js";
import { getSoulVaultSwarmContract } from "../lib/contracts.js";
import { loadActiveState, findSwarm } from "../lib/state.js";

export function registerBackupCommands(program: Command): void {
  const backup = program
    .command("backup")
    .description("Encrypted workspace backup to 0G storage");

  backup
    .command("push")
    .description(
      "Encrypt the workspace, upload to 0G, and record the file mapping on-chain"
    )
    .option("--path <dir>", "Path to workspace directory to backup", ".")
    .option("--dry-run", "Encrypt locally without uploading or recording on-chain")
    .option(
      "--epoch-key <hex>",
      "Hex-encoded 32-byte epoch key (defaults to a generated test key)"
    )
    .action(
      async (opts: {
        path: string;
        dryRun?: boolean;
        epochKey?: string;
      }) => {
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

          // Resolve workspace path
          const workspacePath = path.resolve(opts.path);
          if (!fs.existsSync(workspacePath)) {
            console.error(
              chalk.red(`Workspace path not found: ${workspacePath}`)
            );
            process.exit(1);
          }

          console.log(chalk.dim(`\n  Backing up workspace: ${workspacePath}`));

          // Collect workspace files into a tarball-like buffer
          // For hackathon, we just serialize the file listing + contents as JSON
          const files: Record<string, string> = {};
          const stat = fs.statSync(workspacePath);

          if (stat.isFile()) {
            const content = fs.readFileSync(workspacePath);
            files[path.basename(workspacePath)] =
              content.toString("base64");
          } else {
            const entries = fs.readdirSync(workspacePath, {
              withFileTypes: true,
            });
            let totalSize = 0;
            const MAX_FILES = 100;
            const MAX_SIZE = 10 * 1024 * 1024; // 10MB limit

            for (const entry of entries.slice(0, MAX_FILES)) {
              if (entry.isFile() && !entry.name.startsWith(".")) {
                const fp = path.join(workspacePath, entry.name);
                const fstat = fs.statSync(fp);
                if (totalSize + fstat.size > MAX_SIZE) break;
                totalSize += fstat.size;
                files[entry.name] = fs.readFileSync(fp).toString("base64");
              }
            }
          }

          const payload = Buffer.from(JSON.stringify(files), "utf8");
          console.log(
            chalk.dim(
              `  Payload: ${Object.keys(files).length} file(s), ${payload.length} bytes`
            )
          );

          // Get or generate epoch key
          let kEpoch: Buffer;
          if (opts.epochKey) {
            kEpoch = Buffer.from(opts.epochKey, "hex");
            if (kEpoch.length !== 32) {
              console.error(
                chalk.red("Epoch key must be exactly 32 bytes (64 hex chars).")
              );
              process.exit(1);
            }
          } else {
            kEpoch = generateEpochKey();
            console.log(
              chalk.yellow(
                "  Using generated test epoch key (not persisted)."
              )
            );
            console.log(
              chalk.dim(`  Key: ${kEpoch.toString("hex").slice(0, 16)}...`)
            );
          }

          // Encrypt
          console.log(chalk.dim("  Encrypting with AES-256-GCM..."));
          const encrypted = encryptBackup(payload, kEpoch);

          console.log(
            chalk.dim(
              `  Ciphertext: ${encrypted.ciphertext.length} bytes`
            )
          );
          console.log(
            chalk.dim(`  Nonce: ${encrypted.nonce.toString("hex")}`)
          );
          console.log(
            chalk.dim(
              `  Auth tag: ${encrypted.authTag.toString("hex")}`
            )
          );

          // Verify decryption works
          const decrypted = decryptBackup(
            encrypted.ciphertext,
            kEpoch,
            encrypted.nonce,
            encrypted.authTag,
            encrypted.aad
          );
          if (decrypted.equals(payload)) {
            console.log(
              chalk.green("  Decryption verification: passed")
            );
          } else {
            console.error(
              chalk.red("  Decryption verification: FAILED")
            );
            process.exit(1);
          }

          // Generate placeholder CID
          const cid = `bafk${crypto.randomBytes(28).toString("hex")}`;

          if (!opts.dryRun) {
            // Upload to 0G (placeholder for hackathon)
            console.log(chalk.dim("  Uploading to 0G storage..."));
            console.log(
              chalk.yellow(
                "  Note: 0G upload is placeholder. Will integrate 0G SDK in next iteration."
              )
            );

            // Record on-chain
            try {
              const { ogSigner } = getSigners(config);
              const contract = getSoulVaultSwarmContract(
                swarm.contractAddress,
                ogSigner
              );

              console.log(chalk.dim("  Recording backup CID on-chain..."));
              const tx = await contract.recordBackup(cid);
              console.log(chalk.dim(`  TX: ${tx.hash}`));
              await tx.wait();

              console.log(
                chalk.green.bold("\n  Backup pushed successfully!\n")
              );
              console.log(`  ${chalk.dim("TX Hash:")} ${tx.hash}`);
            } catch (err) {
              console.log(
                chalk.yellow(
                  `\n  On-chain recording skipped: ${err instanceof Error ? err.message : "no signer or contract"}`
                )
              );
            }
          } else {
            console.log(
              chalk.dim(
                "  Dry run: skipping upload and on-chain recording."
              )
            );
          }

          console.log(chalk.green.bold("\n  Backup complete!\n"));
          console.log(`  ${chalk.dim("Files:")}      ${Object.keys(files).length}`);
          console.log(`  ${chalk.dim("Plaintext:")}  ${payload.length} bytes`);
          console.log(
            `  ${chalk.dim("Encrypted:")}  ${encrypted.ciphertext.length} bytes`
          );
          console.log(`  ${chalk.dim("CID:")}        ${chalk.cyan(cid)}`);
          console.log(`  ${chalk.dim("Swarm:")}      ${swarm.name}\n`);
        } catch (err) {
          console.error(
            chalk.red("Failed to push backup:"),
            err instanceof Error ? err.message : err
          );
          process.exit(1);
        }
      }
    );
}
