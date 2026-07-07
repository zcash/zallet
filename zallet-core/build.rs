use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::{Command, CommandFactory, ValueEnum};
use clap_complete::{Shell, generate_to};
use clap_mangen::Man;
use flate2::{Compression, write::GzEncoder};
use i18n_embed::unic_langid::LanguageIdentifier;
use shadow_rs::ShadowBuilder;

#[cfg(not(debug_assertions))]
use std::collections::BTreeMap;

const JSON_RPC_METHODS_RS: &str = "src/components/json_rpc/methods.rs";

mod i18n {
    include!("src/i18n.rs");
}
mod zallet {
    include!("src/cli.rs");
}

#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!($crate::i18n::LANGUAGE_LOADER, $message_id)
    }};

    ($message_id:literal, $($args:expr),* $(,)?) => {{
        i18n_embed_fl::fl!($crate::i18n::LANGUAGE_LOADER, $message_id, $($args), *)
    }};
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src/cli.rs");
    println!("cargo::rerun-if-changed=src/i18n.rs");
    println!("cargo::rerun-if-changed={JSON_RPC_METHODS_RS}");

    // Expose a cfg option so we can make parts of the CLI conditional on not being built
    // within the buildscript.
    println!("cargo:rustc-cfg=outside_buildscript");

    // If `zallet_build` is not set to a known value, use the default "wallet" build.
    #[cfg(not(any(zallet_build = "merchant_terminal", zallet_build = "wallet")))]
    println!("cargo:rustc-cfg=zallet_build=\"wallet\"");

    let out_dir = match env::var_os("OUT_DIR") {
        None => return Ok(()),
        Some(out_dir) => PathBuf::from(out_dir),
    };

    // `OUT_DIR` is "intentionally opaque as it is only intended for `rustc` interaction"
    // (https://github.com/rust-lang/cargo/issues/9858). Peek into the black box and use
    // it to figure out where the target directory is.
    let target_dir = out_dir
        .ancestors()
        .nth(3)
        .expect("should be absolute path")
        .to_path_buf();

    // Collect build-time information.
    ShadowBuilder::builder().build()?;

    // TODO: Improve the build script so this works with non-wallet Zallet builds.
    #[cfg(not(zallet_build = "merchant_terminal"))]
    generate_rpc_openrpc(&out_dir)?;

    // Generate the Debian copyright file.
    #[cfg(not(debug_assertions))]
    generate_debian_copyright(&target_dir)?;

    // Generate the completions in English, because these aren't easily localizable.
    i18n::load_languages(&[]);
    Cli::build().generate_completions(&target_dir.join("completions"))?;

    // Generate manpages for all supported languages.
    let manpage_dir = target_dir.join("manpages");
    for lang_dir in fs::read_dir("./i18n")? {
        let lang_dir = lang_dir?.file_name();
        let lang_dir = lang_dir.to_str().expect("should be valid Unicode");
        println!("cargo::rerun-if-changed=i18n/{lang_dir}/zallet.ftl");

        let lang: LanguageIdentifier = lang_dir
            .parse()
            .expect("should be valid language identifier");

        // Render the manpages into the correct folder structure, so that local checks can
        // be performed with `man -M target/debug/manpages BINARY_NAME`.
        let mut out_dir = if lang.language.as_str() == "en" {
            manpage_dir.clone()
        } else {
            let mut lang_str = lang.language.as_str().to_owned();
            if let Some(region) = lang.region {
                // Locales for manpages use the POSIX format with underscores.
                lang_str += "_";
                lang_str += region.as_str();
            }
            manpage_dir.join(lang_str)
        };
        out_dir.push("man1");

        i18n::load_languages(&[lang]);
        Cli::build().generate_manpages(&out_dir)?;
    }

    Ok(())
}

#[derive(Clone)]
struct Cli {
    zallet: Command,
}

impl Cli {
    fn build() -> Self {
        Self {
            zallet: zallet::EntryPoint::command(),
        }
    }

    fn generate_completions(&mut self, out_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(out_dir)?;

        for &shell in Shell::value_variants() {
            generate_to(shell, &mut self.zallet, "zallet", out_dir)?;
        }

        Ok(())
    }

    fn generate_manpages(self, out_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(out_dir)?;

        fn generate_manpage(
            out_dir: &Path,
            name: &str,
            cmd: Command,
            custom: impl FnOnce(&Man, &mut GzEncoder<fs::File>) -> io::Result<()>,
        ) -> io::Result<()> {
            let file = fs::File::create(out_dir.join(format!("{name}.1.gz")))?;
            let mut w = GzEncoder::new(file, Compression::best());

            let man = Man::new(cmd);
            man.render_title(&mut w)?;
            man.render_name_section(&mut w)?;
            man.render_synopsis_section(&mut w)?;
            man.render_description_section(&mut w)?;
            man.render_options_section(&mut w)?;
            custom(&man, &mut w)?;
            man.render_version_section(&mut w)?;
            man.render_authors_section(&mut w)
        }

        generate_manpage(
            out_dir,
            "zallet",
            self.zallet
                .about(fl!("man-zallet-about"))
                .long_about(fl!("man-zallet-description")),
            |_, _| Ok(()),
        )?;

        Ok(())
    }
}

#[cfg(not(zallet_build = "merchant_terminal"))]
fn generate_rpc_openrpc(out_dir: &Path) -> Result<(), Box<dyn Error>> {
    use quote::ToTokens;

    // Parse the source file containing the `Rpc` trait.
    let methods_rs = fs::read_to_string(JSON_RPC_METHODS_RS)?;
    let methods_ast = syn::parse_file(&methods_rs)?;

    let rpc_trait = methods_ast
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Trait(item_trait) if item_trait.ident == "Rpc" => Some(item_trait),
            _ => None,
        })
        .expect("present");
    let wallet_rpc_trait = methods_ast
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Trait(item_trait) if item_trait.ident == "WalletRpc" => Some(item_trait),
            _ => None,
        })
        .expect("present");

    let mut contents = "#[allow(unused_qualifications)]
pub(super) static METHODS: ::phf::Map<&str, RpcMethod> = ::phf::phf_map! {
"
    .to_string();

    for item in rpc_trait.items.iter().chain(&wallet_rpc_trait.items) {
        if let syn::TraitItem::Fn(method) = item {
            // Find methods via their `#[method(name = "command")]` attribute.
            let mut command = None;
            method
                .attrs
                .iter()
                .find(|attr| attr.path().is_ident("method"))
                .and_then(|attr| {
                    attr.parse_nested_meta(|meta| {
                        command = Some(meta.value()?.parse::<syn::LitStr>()?.value());
                        Ok(())
                    })
                    .ok()
                });

            if let Some(command) = command {
                let module = match &method.sig.output {
                    syn::ReturnType::Type(_, ret) => match ret.as_ref() {
                        syn::Type::Path(type_path) => type_path.path.segments.first(),
                        _ => None,
                    },
                    _ => None,
                }
                .expect("required")
                .ident
                .to_string();

                let params = method.sig.inputs.iter().filter_map(|arg| match arg {
                    syn::FnArg::Receiver(_) => None,
                    syn::FnArg::Typed(pat_type) => match pat_type.pat.as_ref() {
                        syn::Pat::Ident(pat_ident) => {
                            let parameter = pat_ident.ident.to_string();
                            let rust_ty = pat_type.ty.as_ref();

                            // If we can determine the parameter's optionality, do so.
                            let (param_ty, required) = match rust_ty {
                                syn::Type::Path(type_path) => {
                                    let is_standalone_ident =
                                        type_path.path.leading_colon.is_none()
                                            && type_path.path.segments.len() == 1;
                                    let first_segment = &type_path.path.segments[0];

                                    if first_segment.ident == "Option" && is_standalone_ident {
                                        // Strip the `Option<_>` for the schema type.
                                        let schema_ty = match &first_segment.arguments {
                                            syn::PathArguments::AngleBracketed(args) => {
                                                match args.args.first().expect("valid Option") {
                                                    syn::GenericArgument::Type(ty) => ty,
                                                    _ => panic!("Invalid Option"),
                                                }
                                            }
                                            _ => panic!("Invalid Option"),
                                        };
                                        (schema_ty, Some(false))
                                    } else if first_segment.ident == "Vec" {
                                        // We don't know whether the vec may be empty.
                                        (rust_ty, None)
                                    } else {
                                        (rust_ty, Some(true))
                                    }
                                }
                                _ => (rust_ty, Some(true)),
                            };

                            // Handle a few conversions we know we need.
                            let param_ty = param_ty.to_token_stream().to_string();
                            let schema_ty = match param_ty.as_str() {
                                "age :: secrecy :: SecretString" => "String".into(),
                                _ => param_ty,
                            };

                            Some((parameter, schema_ty, required))
                        }
                        _ => None,
                    },
                });

                contents.push('"');
                contents.push_str(&command);
                contents.push_str("\" => RpcMethod {\n");

                contents.push_str("    description: \"");
                for attr in method
                    .attrs
                    .iter()
                    .filter(|attr| attr.path().is_ident("doc"))
                {
                    if let syn::Meta::NameValue(doc_line) = &attr.meta
                        && let syn::Expr::Lit(docs) = &doc_line.value
                        && let syn::Lit::Str(s) = &docs.lit
                    {
                        // Trim the leading space from the doc comment line.
                        let line = s.value();
                        let trimmed_line = if line.is_empty() { &line } else { &line[1..] };

                        let escaped = trimmed_line.escape_default().collect::<String>();

                        contents.push_str(&escaped);
                        contents.push_str("\\n");
                    }
                }
                contents.push_str("\",\n");

                contents.push_str("    params: |_g| vec![\n");
                for (parameter, schema_ty, required) in params {
                    let param_upper = parameter.to_uppercase();

                    contents.push_str("        _g.param::<");
                    contents.push_str(&schema_ty);
                    contents.push_str(">(\"");
                    contents.push_str(&parameter);
                    contents.push_str("\", super::");
                    contents.push_str(&module);
                    contents.push_str("::PARAM_");
                    contents.push_str(&param_upper);
                    contents.push_str("_DESC, ");
                    match required {
                        Some(required) => contents.push_str(&required.to_string()),
                        None => {
                            // Require a helper const to be present.
                            contents.push_str("super::");
                            contents.push_str(&module);
                            contents.push_str("::PARAM_");
                            contents.push_str(&param_upper);
                            contents.push_str("_REQUIRED");
                        }
                    }
                    contents.push_str("),\n");
                }
                contents.push_str("    ],\n");

                contents.push_str("    result: |g| g.result::<super::");
                contents.push_str(&module);
                contents.push_str("::ResultType>(\"");
                contents.push_str(&command);
                contents.push_str("_result\"),\n");

                contents.push_str("    deprecated: ");
                contents.push_str(
                    &method
                        .attrs
                        .iter()
                        .any(|attr| attr.path().is_ident("deprecated"))
                        .to_string(),
                );
                contents.push_str(",\n");

                contents.push_str("},\n");
            }
        }
    }

    contents.push_str("};");

    let rpc_openrpc_path = out_dir.join("rpc_openrpc.rs");
    fs::write(&rpc_openrpc_path, contents)?;

    Ok(())
}

/// This is slow, so we only run it in release builds.
#[cfg(not(debug_assertions))]
fn generate_debian_copyright(target_dir: &Path) -> Result<(), Box<dyn Error>> {
    let mut contents = "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: zallet

Files:
 *
Copyright: 2024-2025, The Electric Coin Company
License: MIT OR Apache-2.0"
        .to_string();

    let licensing = embed_licensing::collect(embed_licensing::CollectConfig::default())?;

    let zallet_licenses = [spdx::license_id("MIT"), spdx::license_id("Apache-2.0")];
    let mut non_spdx_licenses = BTreeMap::new();

    for package in licensing.packages {
        let name = package.name;
        let (license_name, license_text) = match package.license {
            embed_licensing::CrateLicense::SpdxExpression(expression) => {
                // We can leave out any entries that are covered by the license files we
                // already include for Zallet itself.
                if expression.evaluate(|req| zallet_licenses.contains(&req.license.id())) {
                    continue;
                } else {
                    (expression.to_string(), None)
                }
            }
            embed_licensing::CrateLicense::Other(license_text) => {
                (format!("{name}-license"), Some(license_text))
            }
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

    let copyright_path = target_dir.join("debian-copyright");
    fs::write(&copyright_path, contents)?;

    Ok(())
}
