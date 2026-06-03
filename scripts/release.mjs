#!/usr/bin/env node
/**
 * Release script for build-service
 *
 * Usage: node scripts/release.mjs <current|major|minor|patch>
 *
 * Steps:
 * 1. Check for a clean main branch and required tools
 * 2. Bump version in Cargo.toml and Cargo.lock
 * 3. Update CHANGELOG.md: [Unreleased] -> [version] - date
 * 4. Commit and tag
 * 5. Push commit and tag to remote
 * 6. Create GitHub release with notes from CHANGELOG
 * 7. Add new [Unreleased] section
 * 8. Commit and push
 */

import { execSync } from "child_process";
import { existsSync, readFileSync, unlinkSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const RELEASE_BRANCH = "main";

const BUMP_TYPE = process.argv[2];

if (!["current", "major", "minor", "patch"].includes(BUMP_TYPE)) {
	console.error("Usage: node scripts/release.mjs <current|major|minor|patch>");
	process.exit(1);
}

function run(cmd, options = {}) {
	console.log(`$ ${cmd}`);
	try {
		return execSync(cmd, {
			encoding: "utf-8",
			stdio: options.silent ? "pipe" : "inherit",
			cwd: ROOT,
			...options,
		});
	} catch (e) {
		if (!options.ignoreError) {
			console.error(`Command failed: ${cmd}`);
			process.exit(1);
		}
		return null;
	}
}

function getVersion() {
	const content = readFileSync(join(ROOT, "Cargo.toml"), "utf-8");
	const match = content.match(/\[package\][\s\S]*?\nversion\s*=\s*"([^"]+)"/);
	if (!match) {
		console.error("Could not find version in Cargo.toml [package] section");
		process.exit(1);
	}
	return match[1];
}

function parseVersion(version) {
	const match = version.match(/^(\d+)\.(\d+)\.(\d+)(.*)$/);
	if (!match) {
		console.error(`Current version "${version}" is not valid semver (X.Y.Z)`);
		process.exit(1);
	}

	return {
		major: Number.parseInt(match[1], 10),
		minor: Number.parseInt(match[2], 10),
		patch: Number.parseInt(match[3], 10),
		suffix: match[4] || "",
	};
}

function formatVersion(parts) {
	return `${parts.major}.${parts.minor}.${parts.patch}${parts.suffix}`;
}

function updateCargoTomlVersion(newVersion) {
	const cargoTomlPath = join(ROOT, "Cargo.toml");
	let content = readFileSync(cargoTomlPath, "utf-8");
	const versionRegex = /(\[package\][\s\S]*?\nversion\s*=\s*")[^"]*(")/;
	if (!versionRegex.test(content)) {
		console.error("Cargo.toml [package] version not found");
		process.exit(1);
	}

	content = content.replace(versionRegex, `$1${newVersion}$2`);
	writeFileSync(cargoTomlPath, content);
}

function updateCargoLockVersion(newVersion) {
	const cargoLockPath = join(ROOT, "Cargo.lock");
	if (!existsSync(cargoLockPath)) {
		return;
	}

	let content = readFileSync(cargoLockPath, "utf-8");
	const versionRegex =
		/(\[\[package\]\]\nname = "build-service"\nversion = ")[^"]*(")/;
	if (!versionRegex.test(content)) {
		console.error("Cargo.lock package entry not found for build-service");
		process.exit(1);
	}

	content = content.replace(versionRegex, `$1${newVersion}$2`);
	writeFileSync(cargoLockPath, content);
}

function bumpVersion(bumpType) {
	const currentVersion = getVersion();
	const parts = parseVersion(currentVersion);

	switch (bumpType) {
		case "patch":
			parts.patch += 1;
			parts.suffix = "";
			break;
		case "minor":
			parts.minor += 1;
			parts.patch = 0;
			parts.suffix = "";
			break;
		case "major":
			parts.major += 1;
			parts.minor = 0;
			parts.patch = 0;
			parts.suffix = "";
			break;
		default:
			console.error("Usage: node scripts/release.mjs <current|major|minor|patch>");
			process.exit(1);
	}

	const newVersion = formatVersion(parts);
	updateCargoTomlVersion(newVersion);
	updateCargoLockVersion(newVersion);
	console.log(`  Version updated: ${currentVersion} -> ${newVersion}`);
	return newVersion;
}

function ensureCleanMain() {
	const branch = run("git branch --show-current", { silent: true }).trim();
	if (branch !== RELEASE_BRANCH) {
		console.error(
			`Error: releases must be run from ${RELEASE_BRANCH}; current branch is ${branch || "(detached)"}.`
		);
		process.exit(1);
	}

	const status = run("git status --porcelain", { silent: true });
	if (status && status.trim()) {
		console.error("Error: Uncommitted changes detected. Commit or stash first.");
		console.error(status);
		process.exit(1);
	}
}

function ensureTools() {
	run("git --version", { silent: true });
	run("node --version", { silent: true });
	run("gh --version", { silent: true });
}

function ensureTagAvailable(version) {
	const tagExists = run(`git rev-parse -q --verify refs/tags/v${version}`, {
		silent: true,
		ignoreError: true,
	});
	if (tagExists) {
		console.error(`Error: tag v${version} already exists.`);
		process.exit(1);
	}
}

function updateChangelogForRelease(version) {
	const changelogPath = join(ROOT, "CHANGELOG.md");
	const date = new Date().toISOString().split("T")[0];
	let content = readFileSync(changelogPath, "utf-8");

	if (!content.includes("## [Unreleased]")) {
		console.error("Error: No [Unreleased] section found in CHANGELOG.md");
		process.exit(1);
	}

	content = content.replace(
		/## \[Unreleased\]\n\n_No unreleased changes._/,
		`## [${version}] - ${date}`
	);
	content = content.replace(/## \[Unreleased\]/, `## [${version}] - ${date}`);

	writeFileSync(changelogPath, content);
	console.log(`  Updated CHANGELOG.md: [Unreleased] -> [${version}] - ${date}`);
}

function extractReleaseNotes(version) {
	const changelogPath = join(ROOT, "CHANGELOG.md");
	const content = readFileSync(changelogPath, "utf-8");

	const versionEscaped = version.replace(/\./g, "\\.");
	const regex = new RegExp(
		`## \\[${versionEscaped}\\][^\\n]*\\n([\\s\\S]*?)(?=\\n## \\[|$)`
	);
	const match = content.match(regex);

	if (!match) {
		console.error(`Error: Could not extract release notes for v${version}`);
		process.exit(1);
	}

	return match[1].trim();
}

function addUnreleasedSection() {
	const changelogPath = join(ROOT, "CHANGELOG.md");
	let content = readFileSync(changelogPath, "utf-8");

	const unreleasedSection = "## [Unreleased]\n\n_No unreleased changes._\n\n";
	content = content.replace(/^(# Changelog\n\n)/, `$1${unreleasedSection}`);

	writeFileSync(changelogPath, content);
	console.log("  Added [Unreleased] section to CHANGELOG.md");
}

console.log("\n=== Release Script ===\n");

console.log("Checking release prerequisites...");
ensureCleanMain();
ensureTools();
console.log("  Clean main branch and required tools available\n");

let version;
if (BUMP_TYPE === "current") {
	console.log("Using current Cargo.toml version...");
	version = getVersion();
} else {
	console.log(`Bumping version (${BUMP_TYPE})...`);
	version = bumpVersion(BUMP_TYPE);
	console.log(`  New version: ${version}\n`);
}
ensureTagAvailable(version);
console.log(`  Release version: ${version}\n`);

console.log("Updating CHANGELOG.md...");
updateChangelogForRelease(version);
console.log();

console.log("Committing and tagging...");
run("git add Cargo.toml Cargo.lock CHANGELOG.md");
run(`git commit -m "Release v${version}"`);
run(`git tag v${version}`);
console.log();

console.log("Pushing to remote...");
run("git push origin main");
run(`git push origin v${version}`);
console.log();

console.log("Creating GitHub release...");
const releaseNotes = extractReleaseNotes(version);
const notesFile = join(ROOT, ".release-notes-tmp.md");
writeFileSync(notesFile, releaseNotes);
run(
	`gh release create v${version} --title "v${version}" --notes-file "${notesFile}"`
);
unlinkSync(notesFile);
console.log();

console.log("Adding [Unreleased] section for next cycle...");
addUnreleasedSection();
console.log();

console.log("Committing changelog update...");
run("git add CHANGELOG.md");
run('git commit -m "Prepare for next release"');
run("git push origin main");
console.log();

console.log(`=== Released v${version} ===`);
console.log(`https://github.com/kcosr/build-service/releases/tag/v${version}`);
