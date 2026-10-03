//! Test helper: pin a hot query to an index by running
//! `EXPLAIN QUERY PLAN` against it and failing when SQLite reports a full
//! table `SCAN` instead of an index `SEARCH`.
//!
//! Not gated behind `#[cfg(test)]` — this compiles into the normal
//! library so CONSUMER crates can call it from their OWN `#[test]`
//! functions, pinning a hot query's plan the same way this crate's own
//! stress tests pin a concurrency bound with a plain `assert!`.

use rusqlite::{Connection, Params};

/// Runs `EXPLAIN QUERY PLAN <sql>` with no bound parameters and returns
/// each plan row's `detail` column — the 4th (0-indexed) column of EQP's
/// result set, the human-readable line SQLite's own `.eqp` shell command
/// prints — in plan order.
///
/// For a query that has placeholders, bind them through
/// [`assert_uses_index`] instead; this function always runs with an empty
/// parameter list.
pub fn query_plan(conn: &Connection, sql: &str) -> rusqlite::Result<Vec<String>> {
    query_plan_with_params(conn, sql, [])
}

fn query_plan_with_params<P: Params>(
    conn: &Connection,
    sql: &str,
    params: P,
) -> rusqlite::Result<Vec<String>> {
    let explain_sql = format!("EXPLAIN QUERY PLAN {sql}");
    let mut stmt = conn.prepare(&explain_sql)?;
    let rows = stmt.query_map(params, |row| row.get::<_, String>(3))?;
    rows.collect()
}

/// Runs `EXPLAIN QUERY PLAN` against `sql` (with `params` bound, for a
/// query that has placeholders) and **panics** if any plan line is a full
/// table `SCAN` rather than an index `SEARCH` — i.e. a line starting with
/// `SCAN` that does not also carry `USING INDEX` / `USING COVERING INDEX`.
/// Matches both SQLite's pre-3.38 (`SCAN TABLE t`) and 3.38+ (`SCAN t`) EQP
/// wording: the check only looks for the leading `SCAN` keyword and the
/// absence of an index reference, never the table name's exact position.
///
/// Intended for `#[test]` functions that pin a hot query's plan. Call it
/// AFTER seeding realistic data and creating the indexes the query is
/// meant to use — the planner can legitimately prefer a `SCAN` over a
/// tiny or empty table regardless of what indexes exist, since a scan is
/// genuinely cheaper there, and this guard would then fail on a table
/// shape that was never the hot-path concern.
pub fn assert_uses_index<P: Params>(conn: &Connection, sql: &str, params: P) {
    let plan = query_plan_with_params(conn, sql, params).expect("EXPLAIN QUERY PLAN failed");
    for line in &plan {
        let is_full_scan = line.starts_with("SCAN")
            && !line.contains("USING INDEX")
            && !line.contains("USING COVERING INDEX");
        assert!(
            !is_full_scan,
            "query does a full table SCAN instead of hitting an index:\n  {line}\nfull plan:\n{}",
            plan.join("\n")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("open");
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, k TEXT, v TEXT);
             CREATE INDEX idx_t_k ON t (k);
             INSERT INTO t (k, v) VALUES ('a', 'x'), ('b', 'y'), ('c', 'z');",
        )
        .expect("seed");
        conn
    }

    #[test]
    fn query_plan_reports_a_search_line_for_an_indexed_lookup() {
        let conn = seeded_conn();
        let plan = query_plan(&conn, "SELECT id FROM t WHERE k = 'a'").expect("eqp");
        assert!(
            plan.iter()
                .any(|line| line.contains("SEARCH") && line.contains("idx_t_k")),
            "expected a SEARCH using idx_t_k, got: {plan:?}"
        );
    }

    #[test]
    fn assert_uses_index_passes_a_query_that_hits_the_index() {
        let conn = seeded_conn();
        // Must not panic.
        assert_uses_index(
            &conn,
            "SELECT id FROM t WHERE k = ?1",
            rusqlite::params!["a"],
        );
    }

    #[test]
    fn assert_uses_index_panics_on_a_full_table_scan() {
        let conn = seeded_conn();
        // `v` has no index — the planner must fall back to a full SCAN.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_uses_index(
                &conn,
                "SELECT id FROM t WHERE v = ?1",
                rusqlite::params!["x"],
            );
        }))
        .is_err();
        assert!(
            panicked,
            "a query with no usable index on `v` must trip assert_uses_index"
        );
    }
}
