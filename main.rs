use anyhow::{bail, Context, Result};
use chrono::{DateTime, Local};
use clap::{Parser, Subcommand};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Parser)] // requires `derive` feature
#[command(version, about)]
pub(crate) struct Arguments {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Init,
    Commit,
}

pub const ERROR_EXIT_CODE: i32 = 1;

fn main() {
    let args = Arguments::parse();

    if let Err(err) = run(args) {
        eprintln!("{:?}", err);
        std::process::exit(ERROR_EXIT_CODE);
    }
}

fn run(args: Arguments) -> Result<()> {
    match args.command {
        Command::Init => init()?,
        Command::Commit => commit()?,
    }

    Ok(())
}

const NEOGIT_DIRECTORY: &str = ".git";
const NEOGIT_OBJECTS_DIRECTORY: &str = "objects";
const NEOGIT_REFERENCES_DIRECTORY: &str = "refs/heads";
const NEOGIT_INTERNAL_DIRECTORY: [&str; 2] =
    [NEOGIT_OBJECTS_DIRECTORY, NEOGIT_REFERENCES_DIRECTORY];

fn init() -> Result<()> {
    let root_directory = get_root_directory()?;
    let neogit_directory = get_neogit_directory(&root_directory)?;

    for internal_directory in NEOGIT_INTERNAL_DIRECTORY.iter() {
        let mut internal_directory_path = neogit_directory.clone();
        internal_directory_path.push(internal_directory);

        std::fs::create_dir_all(&internal_directory_path).context(format!(
            "Unable to create the directory {:?}.",
            internal_directory_path
        ))?;
    }

    Ok(())
}

fn get_root_directory() -> Result<PathBuf> {
    std::env::current_dir().context("Unable to open the current directory.")
}

fn get_neogit_directory(root_directory: &PathBuf) -> Result<PathBuf> {
    let mut neogit_directory = root_directory.clone();
    neogit_directory.push(NEOGIT_DIRECTORY);
    Ok(neogit_directory)
}

fn commit() -> Result<()> {
    // TODO - To get around adding the full paths to the commits.
    let root_directory = PathBuf::from(r".");
    let neogit_directory = get_neogit_directory(&root_directory)?;

    if !neogit_directory.exists() {
        bail!("Not in a Git repository, no '.git' folder.");
    }

    let mut objects_directory = neogit_directory.clone();
    objects_directory.push(NEOGIT_OBJECTS_DIRECTORY);

    let tree = get_tree(&root_directory, &objects_directory)?;

    let author = Author::new(
        "DeveloperC".to_string(),
        "DeveloperC@protonmail.com".to_string(),
        Local::now(),
    );

    let commit = Commit::new(&tree, &author, &author, "feat: initial bootstrapped commit");
    write_object_to_filesystem(&objects_directory, &commit)?;
    let branch = "main";
    write_branch_to_head(&neogit_directory, branch)?;
    write_object_id_to_branch(&neogit_directory, commit.get_object_id(), branch)
}

fn get_tree(directory: &PathBuf, objects_directory: &PathBuf) -> Result<Tree> {
    let mut blobs: HashSet<Blob> = HashSet::new();

    let entries = std::fs::read_dir(directory).context("Unable to read entries in directory.")?;

    for entry in entries {
        let entry = entry.context("Unable to read entry.")?;
        let path = entry.path();

        if path.is_file() {
            let file_content = std::fs::read_to_string(&path)
                .context(format!("Unable to read the content of {:?}.", path))?;

            let blob = Blob::new(file_content, path.clone());
            blobs.insert(blob);
        }
    }

    // Write all blobs to filesystems.
    for blob in blobs.iter() {
        write_object_to_filesystem(&objects_directory, blob)?;
    }

    // Build tree referencing all the blobs.
    let tree = Tree::new(blobs);
    write_object_to_filesystem(&objects_directory, &tree)?;
    Ok(tree)
}

pub fn write_object_to_filesystem(objects_directory: &PathBuf, object: &dyn Object) -> Result<()> {
    let (object_directory, object_file) =
        get_object_directory_and_file_paths(objects_directory, object.get_object_id());

    std::fs::create_dir_all(&object_directory).context(format!(
        "Unable to create directory {:?}.",
        object_directory
    ))?;

    let mut tmp_object_file = object_directory.clone();
    tmp_object_file.push(".tmp");

    let mut file = File::create(&tmp_object_file)
        .context(format!("Unable to create the file {:?}.", tmp_object_file))?;
    let compressed_bytes = get_compressed_bytes(object.get_content())?;

    file.write_all(&compressed_bytes).context(format!(
        "Unable to write to the file {:?}.",
        tmp_object_file
    ))?;

    std::fs::rename(&tmp_object_file, &object_file).context(format!(
        "Unable to move the temporary file {:?} to {:?}.",
        tmp_object_file, object_file
    ))
}

fn get_compressed_bytes(content: &[u8]) -> Result<Vec<u8>> {
    let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
    zlib.write_all(content)
        .context("Unable to compress content.")?;
    zlib.finish().context("Unable to compress content.")
}

fn get_object_directory_and_file_paths(
    objects_directory: &PathBuf,
    object_id: &[u8],
) -> (PathBuf, PathBuf) {
    let object_id_hex = hex::encode(object_id);
    let object_directory_name = &object_id_hex[0..2];
    let mut object_directory = objects_directory.clone();
    object_directory.push(object_directory_name);

    let object_file_name = &object_id_hex[2..];
    let mut object_file = object_directory.clone();
    object_file.push(object_file_name);

    (object_directory, object_file)
}

pub fn write_branch_to_head(neogit_directory: &PathBuf, branch: &str) -> Result<()> {
    let mut head_file = neogit_directory.clone();
    head_file.push("HEAD");

    std::fs::write(head_file, format!("ref: refs/heads/{}", branch))
        .context("Unable to write to the HEAD file.")
}

pub fn write_object_id_to_branch(
    neogit_directory: &PathBuf,
    object_id: &[u8],
    branch: &str,
) -> Result<()> {
    let mut branch_file = neogit_directory.clone();
    branch_file.push(format!("{}/{}", NEOGIT_REFERENCES_DIRECTORY, branch));

    File::create(&branch_file)
        .context("Unable to open the branch reference file.")?
        .write_all(hex::encode(object_id).as_ref())
        .context("Unable to write to the HEAD file.")
}

use sha1::{Digest, Sha1};

pub trait Object {
    fn get_object_id(&self) -> &[u8];
    fn get_content(&self) -> &[u8];
}

fn calculate_object_id(content: &[u8]) -> Vec<u8> {
    Sha1::digest(&content).to_vec()
}

#[derive(PartialEq, Eq, Hash)]
pub struct Blob {
    name: PathBuf,
    object_id: Vec<u8>,
    content: Vec<u8>,
}

impl Blob {
    pub fn new(file_content: String, name: PathBuf) -> Self {
        let content = format!("blob {}\x00{}", file_content.len(), file_content)
            .as_bytes()
            .to_vec();

        let blob = Blob {
            name,
            object_id: calculate_object_id(&content),
            content,
        };

        blob
    }

    pub fn get_path(&self) -> &PathBuf {
        &self.name
    }
}

impl Object for Blob {
    fn get_object_id(&self) -> &[u8] {
        &self.object_id
    }

    fn get_content(&self) -> &[u8] {
        &self.content
    }
}

pub struct Tree {
    object_id: Vec<u8>,
    content: Vec<u8>,
}

impl Tree {
    pub fn new(entries: HashSet<Blob>) -> Self {
        let mut sorted_entries: Vec<Blob> = entries.into_iter().collect();
        sorted_entries.sort_by(|a, b| a.get_path().cmp(b.get_path()));

        let mut entries_content: Vec<u8> = vec![];

        for entry in &sorted_entries {
            let entry_name = entry
                .get_path()
                .display()
                .to_string()
                .trim_start_matches("./")
                .to_string();
            let tree_entry = format!("100644 {}\x00", entry_name);
            entries_content.extend(tree_entry.as_bytes());
            entries_content.extend(entry.get_object_id());
        }

        let mut content = format!("tree {}\x00", entries_content.len())
            .as_bytes()
            .to_vec();
        content.extend(entries_content);

        let tree = Tree {
            object_id: calculate_object_id(&content),
            content,
        };

        tree
    }
}

impl Object for Tree {
    fn get_object_id(&self) -> &[u8] {
        &self.object_id
    }

    fn get_content(&self) -> &[u8] {
        &self.content
    }
}

pub struct Author {
    name: String,
    email: String,
    authored_at: DateTime<Local>,
}

impl Author {
    pub fn new(name: String, email: String, authored_at: DateTime<Local>) -> Self {
        Author {
            name,
            email,
            authored_at,
        }
    }
}

impl Display for Author {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} <{}> {}",
            self.name,
            self.email,
            self.authored_at.format("%s %z")
        )
    }
}

pub struct Commit {
    object_id: Vec<u8>,
    content: Vec<u8>,
}

impl Commit {
    pub fn new(tree: &Tree, author: &Author, commiter: &Author, message: &str) -> Self {
        let commit_content = format!(
            "tree {}\nauthor {}\ncommitter {}\n\n{}",
            hex::encode(tree.get_object_id()),
            author,
            commiter,
            message
        );

        let mut content = format!("commit {}\x00", commit_content.len())
            .as_bytes()
            .to_vec();
        content.extend(commit_content.as_bytes());

        let commit = Commit {
            object_id: calculate_object_id(&content),
            content,
        };

        commit
    }
}

impl Object for Commit {
    fn get_object_id(&self) -> &[u8] {
        &self.object_id
    }

    fn get_content(&self) -> &[u8] {
        &self.content
    }
}
