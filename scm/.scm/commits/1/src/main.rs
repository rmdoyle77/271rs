use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SCM_DIR: &str = ".scm";
const COMMITS_DIR: &str = ".scm/commits";
const HEAD_FILE: &str = ".scm/HEAD";

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| {
        eprintln!("usage: scm <commit|revert> [-m message]");
        std::process::exit(1);
    });

    match cmd.as_str() {
        "commit" => {
            let mut message = "commit".to_string();
            let mut last = false;
            for a in args {
                if a == "-m" {
                    last = true;
                    continue;
                }
                if last {
                    message = a;
                    last = false;
                }
            }
            commit(&message)?;
        }
        "revert" => revert()?,
        _ => eprintln!("unknown command"),
    }

    Ok(())
}

fn ensure_repo() -> Result<(), Box<dyn Error>> {
    if !Path::new(SCM_DIR).exists() {
        fs::create_dir(SCM_DIR)?;
        fs::create_dir(COMMITS_DIR)?;
    }
    Ok(())
}

fn read_head() -> Result<u64, Box<dyn Error>> {
    if !Path::new(HEAD_FILE).exists() {
        return Ok(0);
    }
    let s = fs::read_to_string(HEAD_FILE)?.trim().to_string();
    if s.is_empty() {
        return Ok(0);
    }
    Ok(s.parse()?)
}

fn write_head(id: u64) -> Result<(), Box<dyn Error>> {
    let mut f = fs::File::create(HEAD_FILE)?;
    write!(f, "{id}")?;
    Ok(())
}

fn commit(message: &str) -> Result<(), Box<dyn Error>> {
    ensure_repo()?;

    let head = read_head()?;
    let new_id = head + 1;

    let commit_dir = Path::new(COMMITS_DIR).join(new_id.to_string());
    fs::create_dir_all(&commit_dir)?;

    let repo_root = env::current_dir()?;
    let mut file_hashes = Vec::new();

    snapshot_dir(&repo_root, &repo_root, &commit_dir, &mut file_hashes)?;

    let meta = commit_dir.join("meta.txt");
    let mut m = fs::File::create(meta)?;

    writeln!(m, "id:{new_id}")?;
    writeln!(m, "parent:{head}")?;
    writeln!(m, "message:{message}")?;
    for (p, h) in file_hashes {
        writeln!(m, "file:{p}|{h}")?;
    }

    write_head(new_id)?;
    println!("Committed as {new_id}");
    Ok(())
}

fn snapshot_dir(
    root: &Path,
    src: &Path,
    commit_dir: &Path,
    hashes: &mut Vec<(String, String)>
) -> Result<(), Box<dyn Error>> {

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if name == ".scm" {
            continue;
        }

        let meta = entry.metadata()?;
        if meta.is_dir() {
            snapshot_dir(root, &path, commit_dir, hashes)?;
        } else {
            let rel = path.strip_prefix(root)?.to_string_lossy().to_string();
            let dest = commit_dir.join(&rel);

            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }

            fs::copy(&path, &dest)?;
            let hash = compute_hash(&dest)?;
            hashes.push((rel, hash));
        }
    }

    Ok(())
}

fn compute_hash(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn revert() -> Result<(), Box<dyn Error>> {
    ensure_repo()?;

    let head = read_head()?;
    if head <= 1 {
        return Err("no previous commit to revert to".into());
    }

    let parent = head - 1;
    println!("Reverting from {head} → {parent}");

    restore_commit(parent)?;
    write_head(parent)?;

    Ok(())
}

fn restore_commit(id: u64) -> Result<(), Box<dyn Error>> {
    let commit_dir = Path::new(COMMITS_DIR).join(id.to_string());
    let meta_path = commit_dir.join("meta.txt");

    let content = fs::read_to_string(meta_path)?;
    let lines = content.lines();

    let mut files = Vec::new();

    for line in lines {
        if line.starts_with("file:") {
            let (_, data) = line.split_once("file:").unwrap();
            let (path, _) = data.split_once("|").unwrap();
            files.push(path.to_string());
        }
    }

    let repo_root = env::current_dir()?;
    clean_working_tree(&repo_root)?;

    for f in files {
        let src = commit_dir.join(&f);
        let dest = repo_root.join(&f);

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::copy(src, dest)?;
    }

    Ok(())
}

fn clean_working_tree(dir: &Path) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if name == ".scm" {
            continue;
        }

        let meta = entry.metadata()?;
        if meta.is_file() {
            fs::remove_file(&path)?;
        } else if meta.is_dir() {
            clean_working_tree(&path)?;
        }
    }
    Ok(())
}

