//! Regression tests for transact-rs/sqlx#4445:
//! a failed or cancelled nested `begin()` must not roll back the enclosing transaction.
//!
//! These tests use an in-memory SQLite database so they need no external server.
//! The failure case is deterministic: a custom `BEGIN` statement is refused inside a
//! transaction (`Error::InvalidSavePointStatement`), which is enough to trigger the bug.

use futures_util::FutureExt;
use sqlx::{Acquire, Connection, Executor, Sqlite, SqliteConnection, Transaction};

async fn setup() -> anyhow::Result<SqliteConnection> {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await?;
    conn.execute("CREATE TABLE t (tag TEXT)").await?;
    Ok(conn)
}

/// Deterministic case: nested `begin_with("BEGIN")` fails, the outer transaction
/// (and its writes) must survive, and `outer.rollback()` must actually roll back.
#[tokio::test]
async fn failed_nested_begin_keeps_outer_transaction() -> anyhow::Result<()> {
    let mut conn = setup().await?;

    let mut outer: Transaction<'_, Sqlite> = Connection::begin(&mut conn).await?;
    sqlx::query("INSERT INTO t VALUES ('w1')")
        .execute(&mut *outer)
        .await?;

    // Custom BEGIN statements are refused inside a transaction.
    let nested = Connection::begin_with(&mut *outer, "BEGIN").await;
    assert!(
        nested.is_err(),
        "nested begin_with(\"BEGIN\") should fail, got Ok"
    );
    // End the borrow of the outer transaction held by the failed result.
    drop(nested);

    // The outer transaction must still be intact: w1 is visible inside it...
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM t")
        .fetch_one(&mut *outer)
        .await?;
    assert_eq!(
        count, 1,
        "outer transaction lost its writes after failed nested begin"
    );

    // ...and rolling it back must really roll back (not silently succeed).
    outer.rollback().await?;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM t")
        .fetch_one(&mut conn)
        .await?;
    assert_eq!(count, 0, "outer rollback did not roll back w1");

    Ok(())
}

/// Cancellation case: a nested `begin()` dropped mid-flight must not roll back
/// the enclosing transaction either. Polls the future once and drops it; if the
/// begin happened to complete, rolls back that savepoint and retries.
#[tokio::test]
async fn cancelled_nested_begin_keeps_outer_transaction() -> anyhow::Result<()> {
    let mut cancelled = false;

    for _ in 0..100 {
        let mut conn = setup().await?;
        let mut outer: Transaction<'_, Sqlite> = Connection::begin(&mut conn).await?;
        sqlx::query("INSERT INTO t VALUES ('w1')")
            .execute(&mut *outer)
            .await?;

        // Poll the nested begin once and drop it if still pending, which cancels
        // the SAVEPOINT round trip. Scoped so no borrow of `conn` escapes.
        let was_cancelled: bool = {
            match Acquire::begin(&mut *outer).now_or_never() {
                None => true,
                // The begin completed before we could cancel it: unwind the
                // savepoint and retry.
                Some(Ok(nested)) => {
                    nested.rollback().await?;
                    false
                }
                Some(Err(e)) => anyhow::bail!("unexpected error from nested begin: {e:?}"),
            }
        };

        if !was_cancelled {
            continue;
        }
        cancelled = true;

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM t")
            .fetch_one(&mut *outer)
            .await?;
        assert_eq!(
            count, 1,
            "outer transaction lost its writes after cancelled nested begin"
        );

        outer.rollback().await?;

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM t")
            .fetch_one(&mut conn)
            .await?;
        assert_eq!(count, 0, "outer rollback did not roll back w1");

        break;
    }

    assert!(cancelled, "never managed to cancel a nested begin");
    Ok(())
}
