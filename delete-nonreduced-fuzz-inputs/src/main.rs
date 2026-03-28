// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Over time the fuzz engine will reduce inputs (produce a smaller input that
// yields the same coverage statistics). With a growing set of inputs, it could
// be useful to occasionally delete the "old" non-reduced inputs.
//
// This script tries to do so in a way that is as deterministic as possible.
//
// The script should be run on an x86_64 virtual machine with only a minimal
// vanilla Ubuntu Noble 24.04 installed. Ideally, the script was run on
// different architectures or even different OS versions, which come with
// different library packages, but this is left as a future improvement. Also,
// it's recommended to run the script twice to ensure that the results are
// "somewhat" reproducible.

use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// A type for a complete and readable error message.
type AppError = String;
type AppResult = Result<(), AppError>;

/// Apt packages that will be installed.
const APT_PACKAGES: &[&str] = &[
    "git",
    "build-essential",
    "pkg-config",
    "bsdmainutils",
    "python3",
    "cmake",
    "libsqlite3-dev",
    "libevent-dev",
    "libboost-dev",
    "lsb-release",
    "wget",
    "software-properties-common",
    "gnupg",
];
/// Path to the cloned qa-assets repository.
const QA_ASSETS_PATH: &str = "qa-assets";
/// The name of the directory in qa-assets that holds the committed fuzz corpora.
const FUZZ_CORPORA_DIR: &str = "fuzz_corpora";
/// Path to the cloned bitcoin repository.
const BITCOIN_PATH: &str = "bitcoin";
/// Bitcoin build directory.
const BITCOIN_BUILD_DIR: &str = "build_fuzz";

const LLVM_VERSION: &str = "18";
const SANITIZERS: &[&str] = &["fuzzer", "fuzzer,address,undefined,integer"];

fn help(err: &str) -> AppError {
    format!(
        r#"
Error: {err}

Usage: delete-nonreduced-fuzz-inputs
"#
    )
}

fn app() -> AppResult {
    let mut args = env::args().skip(1);
    match args.next() {
        None => {}
        Some(a) if a == "--help" || a == "-h" => {
            if args.next().is_some() {
                Err(help("Too many arguments"))?;
            }
            Err(help("help requested"))?;
        }
        Some(a) => Err(help(&format!("Unexpected argument: {a}")))?,
    }
    install_deps()?;
    clone_and_configure_repositories()?;

    let all_inputs_dir = move_fuzz_inputs()?;
    git_commit_all(QA_ASSETS_PATH, "Delete fuzz inputs")?;

    let fuzz_corpora_dir_path = Path::new(QA_ASSETS_PATH).join(FUZZ_CORPORA_DIR);

    println!("Adding reduced seeds with afl-cmin");
    build_bitcoin_afl()?;
    let fuzz_targets = get_fuzz_targets()?;
    for fuzz_target in &fuzz_targets {
        let input_dir = all_inputs_dir.join(fuzz_target);
        if !input_dir.is_dir() {
            println!("No input corpus for {fuzz_target} (ignoring)");
            continue;
        }
        let output_dir = fuzz_corpora_dir_path.join(fuzz_target);
        run_afl_cmin(fuzz_target, input_dir, output_dir)?;
    }
    // git commit -a does not add untracked files so we add fuzz_corpora manually
    git_add(QA_ASSETS_PATH, FUZZ_CORPORA_DIR)?;
    git_commit_all(QA_ASSETS_PATH, "Reduced inputs for afl-cmin")?;

    for sanitizer in SANITIZERS {
        println!("Adding reduced seeds for sanitizer={sanitizer}");
        build_bitcoin_with_sanitizer(sanitizer)?;
        run_libfuzzer(&all_inputs_dir, &fuzz_corpora_dir_path)?;
        git_add(QA_ASSETS_PATH, FUZZ_CORPORA_DIR)?;
        git_commit_all(QA_ASSETS_PATH, &format!("Reduced inputs for {sanitizer}"))?;
    }

    println!("✨ Saved minimized fuzz corpora. ✨");
    Ok(())
}

fn install_deps() -> AppResult {
    install_apt_deps()?;
    install_llvm()?;
    install_aflpp()
}

fn install_apt_deps() -> AppResult {
    env::set_var("DEBIAN_FRONTEND", "noninteractive");

    if !Command::new("apt")
        .arg("update")
        .status()
        .map_err(|e| format!("failed to spawn apt: {e}"))?
        .success()
    {
        Err("apt update failed".to_string())?;
    }

    let mut install_args: Vec<&str> = vec!["install", "-y"];
    install_args.extend_from_slice(APT_PACKAGES);
    if !Command::new("apt")
        .args(&install_args)
        .status()
        .map_err(|e| format!("failed to spawn apt: {e}"))?
        .success()
    {
        Err("apt install failed".to_string())?;
    }

    Ok(())
}

fn install_llvm() -> AppResult {
    env::set_var("LLVM_VERSION", LLVM_VERSION);

    if !Command::new("wget")
        .arg("https://apt.llvm.org/llvm.sh")
        .status()
        .map_err(|e| format!("failed to spawn wget: {e}"))?
        .success()
    {
        Err("wget failed".to_string())?;
    }

    if !Command::new("bash")
        .args(["llvm.sh", LLVM_VERSION, "all"])
        .status()
        .map_err(|e| format!("failed to spawn bash: {e}"))?
        .success()
    {
        Err("bash llvm.sh failed".to_string())?;
    }

    if !Command::new("sh")
        .args([
            "-c",
            &format!("ln -sv $(which llvm-symbolizer-{LLVM_VERSION}) /usr/bin/llvm-symbolizer"),
        ])
        .status()
        .map_err(|e| format!("failed to spawn sh: {e}"))?
        .success()
    {
        Err("linking llvm-symbolizer failed".to_string())?;
    }

    Ok(())
}

fn install_aflpp() -> AppResult {
    let clone_path = "AFLplusplus";
    git_clone(
        "https://github.com/AFLplusplus/AFLplusplus",
        &["--branch=stable"],
        clone_path,
    )?;
    if !Command::new("make")
        .args([
            "-C",
            clone_path,
            &format!("LLVM_CONFIG=llvm-config-{LLVM_VERSION}"),
            "PERFORMANCE=1",
            "install",
            &format!("-j{}", nproc()),
        ])
        .status()
        .map_err(|e| format!("failed to spawn make: {e}"))?
        .success()
    {
        Err("make install AFLplusplus failed".to_string())?;
    }

    Ok(())
}

fn clone_and_configure_repositories() -> AppResult {
    git_clone(
        "https://github.com/bitcoin-core/qa-assets.git",
        &["--depth=1"],
        QA_ASSETS_PATH,
    )?;
    git_config(
        QA_ASSETS_PATH,
        "user.name",
        "delete_nonreduced_inputs script",
    )?;
    git_config(QA_ASSETS_PATH, "user.email", "noreply@noreply.noreply")?;
    git_clone(
        "https://github.com/bitcoin/bitcoin.git",
        &["--depth=1"],
        BITCOIN_PATH,
    )?;

    Ok(())
}

fn move_fuzz_inputs() -> Result<PathBuf, AppError> {
    let src = Path::new(QA_ASSETS_PATH).join(FUZZ_CORPORA_DIR);
    if !src.is_dir() {
        return Err("fuzz corpora not found".to_string());
    }

    let dst = Path::new("all_inputs");
    if dst.exists() {
        return Err("all_inputs already exists".to_string());
    }
    fs::rename(src, dst).map_err(|e| format!("failed to move fuzz corpora: {e}"))?;

    Ok(dst.to_path_buf())
}

fn git_clone<P: AsRef<Path>>(url: &str, clone_args: &[&str], clone_path: P) -> AppResult {
    if !Command::new("git")
        .arg("clone")
        .args(clone_args)
        .arg(url)
        .arg(clone_path.as_ref())
        .status()
        .map_err(|e| format!("failed to spawn git clone: {e}"))?
        .success()
    {
        return Err("git clone {url} failed".to_string());
    }

    Ok(())
}

fn git_config<P: AsRef<Path>>(repo_path: P, key: &str, value: &str) -> AppResult {
    if !Command::new("git")
        .current_dir(repo_path)
        .args(["config", key, value])
        .status()
        .map_err(|e| format!("failed to spawn git config: {e}"))?
        .success()
    {
        return Err(format!("git config failed"));
    }

    Ok(())
}

fn git_add<P: AsRef<Path>, Q: AsRef<Path>>(repo_path: P, file_path: Q) -> AppResult {
    if !Command::new("git")
        .current_dir(repo_path)
        .arg("add")
        .arg(file_path.as_ref())
        .status()
        .map_err(|e| format!("failed to spawn git add: {e}"))?
        .success()
    {
        return Err("git add failed".to_string());
    }

    Ok(())
}

fn git_commit_all<P: AsRef<Path>>(repo_path: P, message: &str) -> AppResult {
    if !Command::new("git")
        .current_dir(repo_path)
        .args(["commit", "-a", "-m", message])
        .status()
        .map_err(|e| format!("failed to spawn git commit: {e}"))?
        .success()
    {
        return Err("git commit failed".to_string());
    }

    Ok(())
}

fn build_bitcoin_afl() -> AppResult {
    build_bitcoin(&[
        "-DCMAKE_C_COMPILER=afl-clang-fast",
        "-DCMAKE_CXX_COMPILER=afl-clang-fast++",
        "-DBUILD_FOR_FUZZING=ON",
    ])
}

fn build_bitcoin_with_sanitizer(sanitizer: &str) -> AppResult {
    build_bitcoin(&[
        &format!("-DCMAKE_C_COMPILER=clang-{LLVM_VERSION}"),
        &format!("-DCMAKE_CXX_COMPILER=clang++-{LLVM_VERSION}"),
        "-DBUILD_FOR_FUZZING=ON",
        &format!("-DSANITIZERS={sanitizer}"),
    ])
}

fn build_bitcoin(cmake_args: &[&str]) -> AppResult {
    let build_dir = Path::new(BITCOIN_PATH).join(BITCOIN_BUILD_DIR);
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir)
            .map_err(|e| format!("failed to remove {BITCOIN_BUILD_DIR} directory: {e}"))?;
    }

    if !Command::new("cmake")
        .current_dir(BITCOIN_PATH)
        .env("LDFLAGS", "-fuse-ld=lld")
        .args(["-B", BITCOIN_BUILD_DIR])
        .args(cmake_args)
        .status()
        .map_err(|e| format!("failed to run cmake configure: {e}"))?
        .success()
    {
        return Err("CMake configuration failed".to_string());
    }

    if !Command::new("cmake")
        .current_dir(BITCOIN_PATH)
        .args(["--build", BITCOIN_BUILD_DIR, &format!("-j{}", nproc())])
        .status()
        .map_err(|e| format!("failed to build with cmake: {e}"))?
        .success()
    {
        return Err("CMake build failed".to_string());
    }

    Ok(())
}

fn get_fuzz_targets() -> Result<Vec<String>, AppError> {
    let out_path = "/tmp/fuzz_targets";
    if !Command::new(format!("{BITCOIN_BUILD_DIR}/bin/fuzz"))
        .env("WRITE_ALL_FUZZ_TARGETS_AND_ABORT", out_path)
        .current_dir(BITCOIN_PATH)
        .status()
        .map_err(|e| format!("failed to write fuzz targets: {e}"))?
        .success()
    {
        return Err("failed to write fuzz targets".to_string());
    }
    let file =
        fs::File::open(out_path).map_err(|e| format!("could not open file {}: {e}", out_path))?;

    let mut fuzz_targets = Vec::new();
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line.map_err(|e| format!("could not read line in fuzz targets file: {e}"))?;
        let line = line.trim();
        if !line.is_empty() {
            fuzz_targets.push(line.to_owned());
        }
    }
    Ok(fuzz_targets)
}

fn run_afl_cmin<P: AsRef<Path>, Q: AsRef<Path>>(
    fuzz_target: &str,
    input_dir: P,
    output_dir: Q,
) -> AppResult {
    let output_dir = output_dir.as_ref();

    fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create output dir for afl-cmin: {e}"))?;

    if !Command::new("afl-cmin")
        .env("FUZZ", fuzz_target)
        .args([
            "-T",
            "all",
            "-A",
            &format!("-i={}", input_dir.as_ref().display()),
            &format!("-o={}", output_dir.display()),
            "--",
            &format!("{BITCOIN_PATH}/{BITCOIN_BUILD_DIR}/bin/fuzz"),
        ])
        .status()
        .map_err(|e| format!("failed to spawn afl-cmin: {e}"))?
        .success()
    {
        return Err(format!("afl-cmin failed for {fuzz_target}"));
    }
    Ok(())
}

fn run_libfuzzer<P: AsRef<Path>, Q: AsRef<Path>>(input_dir: P, output_dir: Q) -> AppResult {
    // test_runner.py uses libFuzzer
    if !Command::new(format!(
        "{BITCOIN_PATH}/{BITCOIN_BUILD_DIR}/test/fuzz/test_runner.py"
    ))
    .args([
        "-l=DEBUG",
        &format!("--par={}", nproc()),
        &format!("--m_dir={}", input_dir.as_ref().display()),
        &format!("{}", output_dir.as_ref().display()),
    ])
    .status()
    .map_err(|e| format!("failed to spawn test_runner.py: {e}"))?
    .success()
    {
        return Err("test_runner.py failed".to_string());
    }
    Ok(())
}

fn nproc() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn main() -> ExitCode {
    match app() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("⚠️\n{err}");
            ExitCode::FAILURE
        }
    }
}
