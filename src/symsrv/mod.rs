pub mod blocking;
pub mod nonblocking;

use std::{path::PathBuf, str::FromStr};
use thiserror::Error;

/// Information about a symbol file resource.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SymFileInfo {
    Exe(ExeInfo),
    Pdb(PdbInfo),
    /// A raw symsrv-compatible hash.
    RawHash(String),
}

impl ToString for SymFileInfo {
    fn to_string(&self) -> String {
        // The middle component of the resource's path on a symbol.
        match self {
            SymFileInfo::Exe(i) => i.to_string(),
            SymFileInfo::Pdb(i) => i.to_string(),
            SymFileInfo::RawHash(h) => h.clone(),
        }
    }
}

/// Executable file information relevant to a symbol server.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExeInfo {
    pub timestamp: u32,
    pub size: u32,
}

impl ToString for ExeInfo {
    fn to_string(&self) -> String {
        format!("{:08x}{:x}", self.timestamp, self.size)
    }
}

/// PDB file information relevant to a symbol server.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PdbInfo {
    pub guid: u128,
    pub age: u32,
}

impl ToString for PdbInfo {
    fn to_string(&self) -> String {
        format!("{:032X}{:x}", self.guid, self.age)
    }
}

#[derive(Error, Debug)]
pub enum DownloadError {
    /// Server returned a 404 error. Try the next one.
    #[error("server returned 404 not found")]
    FileNotFound,

    #[error("error requesting file")]
    Request(#[from] reqwest::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadStatus {
    /// The symbol file already exists in the filesystem.
    AlreadyExists,
    /// The symbol file was successfully downloaded from the remote server.
    DownloadedOk,
}

/// A symbol server, defined by the user with the syntax `SRV*<cache_path>*<server_url>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymSrvSpec {
    /// The base URL for a symbol server, e.g: `https://msdl.microsoft.com/download/symbols`
    pub server_url: String,
    /// The base path for the local symbol cache, e.g: `C:\Symcache`
    pub cache_path: PathBuf,
}

/// Determines if a symbol store uses a two-tier directory structure.
///
/// A two-tier structure is indicated by the presence of an `index2.txt` file
/// in the root of the symbol store. In this structure, files are organized
/// by the first two characters of the filename:
/// - Single-tier: `<cache>/ntdll.pdb/<hash>/ntdll.pdb`
/// - Two-tier: `<cache>/nt/ntdll.pdb/<hash>/ntdll.pdb`
///
/// Reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-store-folder-tree
pub fn is_two_tier(cache_path: &std::path::Path) -> bool {
    cache_path.join("index2.txt").exists()
}

/// Returns the two-tier prefix for a filename (first two characters, lowercase).
///
/// For filenames shorter than 2 characters, returns the filename itself.
pub fn two_tier_prefix(name: &str) -> String {
    name.chars()
        .take(2)
        .collect::<String>()
        .to_lowercase()
}

impl FromStr for SymSrvSpec {
    type Err = anyhow::Error;

    fn from_str(srv: &str) -> Result<Self, Self::Err> {
        // Split the path out by asterisks.
        let directives: Vec<&str> = srv.split('*').collect();

        // Ensure that the path starts with `SRV*` - the only form we currently support.
        match directives.first() {
            // Simply exit the match statement if the directive is "SRV"
            Some(x) => {
                if x.eq_ignore_ascii_case("SRV") {
                    if directives.len() != 3 {
                        anyhow::bail!("Unsupported server string form; only 'SRV*<CACHE_PATH>*<SYMBOL_SERVER>' supported");
                    }

                    // Alright, the directive is of the proper form. Return the server and filepath.
                    return Ok(SymSrvSpec {
                        server_url: directives[2].to_string(),
                        cache_path: directives[1].into(),
                    });
                }
            }

            None => {
                anyhow::bail!("Unsupported server string form; only 'SRV*<CACHE_PATH>*<SYMBOL_SERVER>' supported");
            }
        };

        anyhow::bail!(
            "Unsupported server string form; only 'SRV*<CACHE_PATH>*<SYMBOL_SERVER>' supported"
        );
    }
}

impl std::fmt::Display for SymSrvSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SRV*{}*{}", self.cache_path.display(), self.server_url)
    }
}

/// A list of symbol servers, defined by the user with a semicolon-separated list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymSrvList(pub Box<[SymSrvSpec]>);

impl FromStr for SymSrvList {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let server_list: Vec<&str> = s.split(';').collect();
        if server_list.is_empty() {
            anyhow::bail!("Invalid server string");
        }

        let vec = server_list
            .into_iter()
            .map(|symstr| symstr.parse::<SymSrvSpec>())
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(SymSrvList(vec.into_boxed_slice()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn symsrv_spec() {
        assert_eq!(
            SymSrvSpec::from_str("SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols")
                .unwrap(),
            SymSrvSpec {
                server_url: "https://msdl.microsoft.com/download/symbols".to_string(),
                cache_path: "C:\\Symbols".into(),
            }
        );

        assert_eq!(
            SymSrvSpec::from_str("srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols")
                .unwrap(),
            SymSrvSpec {
                server_url: "https://msdl.microsoft.com/download/symbols".to_string(),
                cache_path: "C:\\Symbols".into(),
            }
        );
    }

    #[test]
    fn test_two_tier_prefix() {
        // Normal filenames
        assert_eq!(two_tier_prefix("ntdll.pdb"), "nt");
        assert_eq!(two_tier_prefix("kernel32.pdb"), "ke");
        assert_eq!(two_tier_prefix("NTDLL.PDB"), "nt"); // Should be lowercase
        assert_eq!(two_tier_prefix("Kernel32.dll"), "ke");
        
        // Edge cases - first two characters regardless of filename structure
        assert_eq!(two_tier_prefix("a.pdb"), "a."); // Only 1 char before dot, takes 'a.'
        assert_eq!(two_tier_prefix("ab"), "ab");
        assert_eq!(two_tier_prefix("a"), "a");
        assert_eq!(two_tier_prefix(""), "");
    }

    #[test]
    fn test_is_two_tier() {
        use std::fs;
        use tempfile::tempdir;

        // Create a temporary directory for testing
        let temp_dir = tempdir().expect("failed to create temp dir");

        // Without index2.txt, should be single-tier
        assert!(!is_two_tier(temp_dir.path()));

        // Create index2.txt
        fs::write(temp_dir.path().join("index2.txt"), "").expect("failed to create index2.txt");

        // With index2.txt, should be two-tier
        assert!(is_two_tier(temp_dir.path()));
    }
}
