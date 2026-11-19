//! Canonical secret source paths.

use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::io::validate_slug;

/// The closed set of source categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Signing,
    Ssh,
    Ai,
    Forge,
    Registry,
    Oauth,
    Cloud,
    App,
    System,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            self.to_possible_value()
                .expect("all categories have names")
                .get_name(),
        )
    }
}

impl FromStr for Category {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        <Self as ValueEnum>::from_str(value, false)
    }
}

/// Custody scope of a source.
#[derive(Clone, Copy, Debug)]
pub enum Owner<'a> {
    Home(&'a str),
    Host(&'a str),
    Module,
}

/// The source's custody tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tree {
    Home,
    Root,
}

/// Components of a canonical source path.
#[derive(Debug, Eq, PartialEq)]
pub struct SourceId {
    pub tree: Tree,
    pub scope: String,
    pub category: Category,
    pub name: String,
}

/// Construct a source path. Panics if a scope or name is not a valid slug.
pub fn source_path(owner: Owner<'_>, category: Category, name: &str) -> PathBuf {
    assert!(validate_slug(name).is_ok(), "invalid source name");
    let mut path = PathBuf::from("age/secrets");
    match owner {
        Owner::Home(scope) => {
            assert!(validate_slug(scope).is_ok(), "invalid home scope");
            path.extend(["home", scope]);
        }
        Owner::Host(scope) => {
            assert!(validate_slug(scope).is_ok(), "invalid host scope");
            path.extend(["root", "hosts", scope]);
        }
        Owner::Module => path.extend(["root", "modules"]),
    }
    path.push(category.to_string());
    path.push(format!("{name}.age"));
    path
}

/// Parse only canonical, relative source paths with valid slug components.
pub fn parse(rel: &Path) -> Option<SourceId> {
    let parts: Vec<_> = rel
        .components()
        .map(|c| match c {
            Component::Normal(v) => v.to_str(),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let (tree, scope, category, file) = match parts.as_slice() {
        ["age", "secrets", "home", scope, category, file] => (Tree::Home, *scope, *category, *file),
        ["age", "secrets", "root", "hosts", scope, category, file] => {
            (Tree::Root, *scope, *category, *file)
        }
        ["age", "secrets", "root", "modules", category, file] => {
            (Tree::Root, "modules", *category, *file)
        }
        _ => return None,
    };
    let name = file.strip_suffix(".age")?;
    validate_slug(scope).ok()?;
    validate_slug(name).ok()?;
    Some(SourceId {
        tree,
        scope: scope.to_owned(),
        category: category.parse().ok()?,
        name: name.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn round_trip_and_reject_invalid_paths() {
        for owner in [
            Owner::Home("can"),
            Owner::Home("shared"),
            Owner::Host("atlas"),
            Owner::Module,
        ] {
            let path = source_path(owner, Category::Oauth, "client_secret");
            let id = parse(&path).unwrap();
            assert_eq!(id.category, Category::Oauth);
            assert_eq!(id.name, "client_secret");
        }
        for path in [
            "/age/secrets/home/can/oauth/a.age",
            "age/secrets/home/../oauth/a.age",
            "age/secrets/home/can/unknown/a.age",
            "age/secrets/root/hosts/atlas/oauth/a/b.age",
            "age/secrets/home/can/oauth/a.txt",
        ] {
            assert!(parse(Path::new(path)).is_none(), "{path}");
        }
    }
}
