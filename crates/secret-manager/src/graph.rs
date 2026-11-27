//! Declarative action graph: a secret flow is a list of [`Node`]s (id, deps,
//! action) run by one interpreter in Kahn topological order. A failed node
//! blocks its transitive dependents; independent branches keep running.

use std::collections::HashMap;

use anyhow::{Result, bail};

/// One step in a declarative secret-management flow.
pub struct Node<'a> {
    pub id: &'static str,
    pub deps: Vec<&'static str>,
    pub action: Box<dyn FnOnce() -> Result<()> + 'a>,
}

impl<'a> Node<'a> {
    /// Construct a node with its static identifier, declared dependencies, and action.
    pub fn new(
        id: &'static str,
        deps: &[&'static str],
        action: impl FnOnce() -> Result<()> + 'a,
    ) -> Self {
        Self {
            id,
            deps: deps.to_vec(),
            action: Box::new(action),
        }
    }
}

/// Outcome of a single [`Node`] after [`execute`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Done,
    Failed(String),
    /// Not run because this dependency failed or was itself blocked.
    Blocked(&'static str),
    /// Dry run: planned only.
    Skipped,
}

/// Node outcomes in execution order.
#[derive(Debug)]
pub struct Report(pub Vec<(&'static str, Status)>);

impl Report {
    /// Look up the outcome of a node by its identifier.
    pub fn status(&self, id: &str) -> Option<&Status> {
        self.0.iter().find(|(n, _)| *n == id).map(|(_, s)| s)
    }

    /// Err if any node failed or was blocked, naming each.
    pub fn into_result(self) -> Result<Self> {
        let bad: Vec<String> = self
            .0
            .iter()
            .filter_map(|(id, s)| match s {
                Status::Failed(m) => Some(format!("{id} failed: {m}")),
                Status::Blocked(by) => Some(format!("{id} blocked by {by}")),
                _ => None,
            })
            .collect();
        if bad.is_empty() {
            Ok(self)
        } else {
            bail!("{}", bad.join("; "))
        }
    }
}

/// Kahn order (ties broken by declaration order); rejects duplicate ids,
/// unknown dependencies and cycles before anything runs.
fn order(nodes: &[Node<'_>]) -> Result<Vec<usize>> {
    let mut index = HashMap::new();
    for (i, n) in nodes.iter().enumerate() {
        if index.insert(n.id, i).is_some() {
            bail!("duplicate node `{}`", n.id);
        }
    }
    let mut pending = vec![0usize; nodes.len()];
    let mut dependents = vec![Vec::new(); nodes.len()];
    for (i, n) in nodes.iter().enumerate() {
        for dep in &n.deps {
            let Some(&d) = index.get(dep) else {
                bail!("node `{}` depends on unknown node `{dep}`", n.id);
            };
            pending[i] += 1;
            dependents[d].push(i);
        }
    }
    let mut ready: Vec<usize> = (0..nodes.len()).filter(|&i| pending[i] == 0).collect();
    let mut out = Vec::with_capacity(nodes.len());
    while !ready.is_empty() {
        let i = ready.remove(ready.iter().enumerate().min_by_key(|(_, v)| **v).unwrap().0);
        out.push(i);
        for &d in &dependents[i] {
            pending[d] -= 1;
            if pending[d] == 0 {
                ready.push(d);
            }
        }
    }
    if out.len() != nodes.len() {
        let stuck: Vec<_> = (0..nodes.len())
            .filter(|i| !out.contains(i))
            .map(|i| nodes[i].id)
            .collect();
        bail!("dependency cycle among: {}", stuck.join(", "));
    }
    Ok(out)
}

/// Run the graph. `Err` means the graph itself is invalid; node failures are
/// in the report (see [`Report::into_result`]). A dry run prints the ordered
/// plan and executes nothing.
pub fn execute(nodes: Vec<Node<'_>>, dry_run: bool) -> Result<Report> {
    let order = order(&nodes)?;
    let mut slots: Vec<Option<Node<'_>>> = nodes.into_iter().map(Some).collect();
    let mut status: HashMap<&'static str, Status> = HashMap::new();
    let mut report = Vec::new();
    for (step, i) in order.into_iter().enumerate() {
        let node = slots[i].take().expect("each node runs once");
        let st = if dry_run {
            eprintln!(
                "{}. {} (after: {})",
                step + 1,
                node.id,
                node.deps.join(", ")
            );
            Status::Skipped
        } else if let Some(by) = node
            .deps
            .iter()
            .find(|d| matches!(status[*d], Status::Failed(_) | Status::Blocked(_)))
        {
            eprintln!("-- {} blocked by {by}", node.id);
            Status::Blocked(by)
        } else {
            eprintln!("-- {}", node.id);
            match (node.action)() {
                Ok(()) => Status::Done,
                Err(e) => {
                    eprintln!("-- {} failed: {e:#}", node.id);
                    Status::Failed(format!("{e:#}"))
                }
            }
        };
        status.insert(node.id, st.clone());
        report.push((node.id, st));
    }
    Ok(Report(report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn log_node<'a>(
        log: &'a RefCell<Vec<&'static str>>,
        id: &'static str,
        deps: &[&'static str],
        ok: bool,
    ) -> Node<'a> {
        Node::new(id, deps, move || {
            log.borrow_mut().push(id);
            if ok { Ok(()) } else { bail!("boom") }
        })
    }

    #[test]
    fn runs_in_dependency_order() {
        let log = RefCell::new(Vec::new());
        // Declared out of order; c needs b needs a.
        let nodes = vec![
            log_node(&log, "c", &["b"], true),
            log_node(&log, "a", &[], true),
            log_node(&log, "b", &["a"], true),
        ];
        execute(nodes, false).unwrap().into_result().unwrap();
        assert_eq!(*log.borrow(), ["a", "b", "c"]);
    }

    #[test]
    fn rejects_cycles_unknown_deps_and_duplicates() {
        let log = RefCell::new(Vec::new());
        let cycle = vec![
            log_node(&log, "a", &["b"], true),
            log_node(&log, "b", &["a"], true),
        ];
        assert!(
            execute(cycle, false)
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );
        let unknown = vec![log_node(&log, "a", &["zzz"], true)];
        assert!(
            execute(unknown, false)
                .unwrap_err()
                .to_string()
                .contains("unknown")
        );
        let dup = vec![
            log_node(&log, "a", &[], true),
            log_node(&log, "a", &[], true),
        ];
        assert!(
            execute(dup, false)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        assert!(log.borrow().is_empty(), "validation runs before any action");
    }

    #[test]
    fn failure_blocks_dependents_not_siblings() {
        let log = RefCell::new(Vec::new());
        let nodes = vec![
            log_node(&log, "bad", &[], false),
            log_node(&log, "child", &["bad"], true),
            log_node(&log, "grandchild", &["child"], true),
            log_node(&log, "sibling", &[], true),
        ];
        let report = execute(nodes, false).unwrap();
        assert_eq!(*log.borrow(), ["bad", "sibling"]);
        assert!(matches!(report.status("bad"), Some(Status::Failed(m)) if m == "boom"));
        assert_eq!(report.status("child"), Some(&Status::Blocked("bad")));
        assert_eq!(report.status("grandchild"), Some(&Status::Blocked("child")));
        assert_eq!(report.status("sibling"), Some(&Status::Done));
        assert!(report.into_result().is_err());
    }

    #[test]
    fn dry_run_runs_nothing() {
        let log = RefCell::new(Vec::new());
        let nodes = vec![
            log_node(&log, "a", &[], true),
            log_node(&log, "b", &["a"], false),
        ];
        let report = execute(nodes, true).unwrap();
        assert!(log.borrow().is_empty());
        assert_eq!(report.status("b"), Some(&Status::Skipped));
        assert!(report.into_result().is_ok());
    }
}
