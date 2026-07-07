//! Generates the Debian copyright file for the union of the dependency graphs
//! of every binary the `zallet` deb ships.
//!
//! The deb contains three binaries built from three separate cargo workspaces
//! (the `zallet` launcher, `zallet-zebra`, and `zallet-zaino`), so a
//! single build-script collection pass cannot see all shipped code. This tool
//! resolves each binary's graph — locked, with the exact feature set the
//! release builds use — and emits one merged machine-readable copyright file.
//!
//! Run from anywhere: `cargo run --release -p gen-copyright -- --out <path>`.
//! The stanza format matches what zallet-core's build script produced before
//! zcash/zallet#540 phase 4 moved generation here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::{env, fs};

use cargo_metadata::{CargoOpt, DependencyKind, MetadataCommand, Package};
use embed_licensing_core::{Crate, CrateLicense};

/// Builds licensing info for a package.
///
/// Equivalent to `embed_licensing_core::Crate::try_from` except that a missing
/// website is tolerated (the copyright output doesn't use it, and git
/// dependencies like zewif-zcashd legitimately lack homepage/repository
/// fields, which would otherwise abort the whole collection).
fn crate_info(package: &Package) -> Result<Crate, Box<dyn Error>> {
    let license = if let Some(expr) = &package.license {
        CrateLicense::SpdxExpression(spdx::Expression::parse_mode(expr, spdx::ParseMode::LAX)?)
    } else if let Some(license_file) = &package.license_file {
        CrateLicense::Other(fs::read_to_string(
            package
                .manifest_path
                .parent()
                .expect("crate manifest path has a parent directory")
                .join(license_file),
        )?)
    } else {
        return Err(format!("no license metadata for {}", package.name).into());
    };
    Ok(Crate {
        name: package.name.clone(),
        version: package.version.to_string(),
        authors: package.authors.clone(),
        license,
        website: package
            .homepage
            .as_deref()
            .or(package.repository.as_deref())
            .or(package.documentation.as_deref())
            .unwrap_or_default()
            .to_string(),
    })
}

/// The binaries the deb ships: manifest path (relative to the repo root) and
/// the feature set the release builds enable.
const SHIPPED: &[(&str, &[&str])] = &[
    ("zallet/Cargo.toml", &[]),
    ("backends/zebra/Cargo.toml", &["zcashd-import", "rpc-cli"]),
    ("backends/zaino/Cargo.toml", &["zcashd-import", "rpc-cli"]),
];

fn repo_root() -> PathBuf {
    // tools/gen-copyright -> tools -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("tool lives two levels below the repo root")
        .to_path_buf()
}

/// Collects the crates reachable through normal (shipped-code) dependencies of
/// the given manifest's root package, resolved against its existing lockfile.
fn graph_crates(manifest: &Path, features: &[&str]) -> Result<BTreeSet<Crate>, Box<dyn Error>> {
    let mut cmd = MetadataCommand::new();
    cmd.manifest_path(manifest);
    if !features.is_empty() {
        cmd.features(CargoOpt::SomeFeatures(
            features.iter().map(|f| f.to_string()).collect(),
        ));
    }
    // Refuse to re-resolve: the copyright file must describe the graphs the
    // release binaries were actually built from.
    cmd.other_options(vec!["--locked".to_string()]);
    let metadata = cmd.exec()?;

    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or("cargo metadata returned no dependency graph")?;
    let nodes: HashMap<_, _> = resolve.nodes.iter().map(|n| (&n.id, n)).collect();
    let root = resolve
        .root
        .as_ref()
        .ok_or("cargo metadata returned no root node")?;

    let mut seen = BTreeSet::new();
    let mut queue = vec![root];
    let mut crates = BTreeSet::new();
    while let Some(id) = queue.pop() {
        if !seen.insert(id) {
            continue;
        }
        crates.insert(crate_info(&metadata[id])?);
        for dep in &nodes[id].deps {
            if dep
                .dep_kinds
                .iter()
                .any(|k| k.kind == DependencyKind::Normal)
            {
                queue.push(&dep.pkg);
            }
        }
    }
    Ok(crates)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let out = match args.as_slice() {
        [_, flag, out] if flag == "--out" => PathBuf::from(out),
        _ => return Err("usage: gen-copyright --out <path>".into()),
    };

    let root = repo_root();
    let mut union: BTreeSet<Crate> = BTreeSet::new();
    for (manifest, features) in SHIPPED {
        union.extend(graph_crates(&root.join(manifest), features)?);
    }

    let mut contents = "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: zallet

Files:
 *
Copyright: 2024-2025, The Electric Coin Company
License: MIT OR Apache-2.0"
        .to_string();

    let zallet_licenses = [spdx::license_id("MIT"), spdx::license_id("Apache-2.0")];
    let mut non_spdx_licenses = BTreeMap::new();

    for package in union {
        let name = package.name;
        let (license_name, license_text) = match package.license {
            CrateLicense::SpdxExpression(expression) => {
                // We can leave out any entries that are covered by the license
                // files we already include for Zallet itself.
                if expression.evaluate(|req| zallet_licenses.contains(&req.license.id())) {
                    continue;
                } else {
                    (expression.to_string(), None)
                }
            }
            CrateLicense::Other(license_text) => (format!("{name}-license"), Some(license_text)),
        };

        contents.push_str(&format!(
            "

Files:
 target/release/deps/{name}-*
 target/release/deps/lib{name}-*
Copyright:"
        ));
        for author in package.authors {
            contents.push_str("\n ");
            contents.push_str(&author);
        }
        contents.push_str("\nLicense: ");
        contents.push_str(&license_name);
        if let Some(text) = license_text {
            non_spdx_licenses.insert(license_name, text);
        }
    }
    contents.push('\n');

    for (license_name, license_text) in non_spdx_licenses {
        contents.push_str("\nLicense: ");
        contents.push_str(&license_name);
        for line in license_text.lines() {
            contents.push_str("\n ");
            if line.is_empty() {
                contents.push('.');
            } else {
                contents.push_str(line);
            }
        }
    }

    fs::write(&out, contents)?;
    eprintln!("wrote {}", out.display());
    Ok(())
}
