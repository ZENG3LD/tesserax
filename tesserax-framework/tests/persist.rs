//! Feature `store`: an effect becomes one batch write; the kernel hears
//! "persisted" only after the durability barrier, with the effect's ticket.
#![cfg(feature = "store")]

use std::time::{Duration, Instant};

use tesserax::swc::{
    CommandId, Generation, ObservationEnvelope, Port, Reject, RejectCode, Subject,
};
use tesserax_framework::{
    Core, Domain, PersistConfig, PersistExecutor, PersistOutcome, Runtime, RuntimeConfig, Tick,
};
use tesserax_store::{Db, DbConfig, Migration, MigrationRunner};

/// Records to write; each is acknowledged once durable.
#[derive(Default)]
struct Ledger {
    acks: Vec<(u64, PersistOutcome)>,
}

impl Domain for Ledger {
    type Command = i64;
    type Effect = i64;
    type Observation = PersistOutcome;
    type Event = ();
    type State = Vec<(u64, PersistOutcome)>;

    fn apply_command(
        &mut self,
        tick: &mut Tick<'_, Self>,
        _id: CommandId,
        value: i64,
    ) -> Result<(), Reject> {
        if value < 0 {
            return Err(Reject::new(RejectCode::Invalid, "negative"));
        }
        tick.effect(None, Generation::default(), value)?;
        Ok(())
    }

    fn generation_of(&self, _: Subject) -> Option<Generation> {
        None
    }

    fn apply_observation(
        &mut self,
        _: &mut Tick<'_, Self>,
        o: ObservationEnvelope<PersistOutcome>,
    ) {
        self.acks
            .push((o.operation_id.map_or(0, |op| op.0), o.observation));
    }

    fn project(&self) -> Self::State {
        self.acks.clone()
    }
}

fn db() -> Db {
    let db = Db::open(&DbConfig::in_memory()).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(db.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "t",
            "CREATE TABLE t (n INTEGER PRIMARY KEY);",
        )])))
        .unwrap();
    db
}

#[test]
fn writes_are_acknowledged_after_the_barrier() {
    let db = db();
    let executor = PersistExecutor::new(
        &db,
        PersistConfig::default(),
        |effect: tesserax::swc::EffectEnvelope<i64>| {
            let n = effect.effect;
            Box::new(move |conn: &tesserax_store::rusqlite::Connection| {
                conn.execute("INSERT INTO t VALUES (?1)", [n])?;
                Ok(())
            })
        },
        |_, outcome| outcome,
    )
    .unwrap();
    let (handle, mut runtime) = Runtime::new(
        Core::new(Ledger::default()),
        RuntimeConfig::default(),
        executor,
    );
    handle.dispatch(1).unwrap();
    handle.dispatch(2).unwrap();
    handle.dispatch(1).unwrap(); // duplicate key: this write fails alone
    runtime.tick();

    let deadline = Instant::now() + Duration::from_secs(10);
    let acks = loop {
        runtime.tick();
        let acks = handle.snapshot().state.clone();
        if acks.len() == 3 {
            break acks;
        }
        assert!(Instant::now() < deadline, "{acks:?}");
        std::thread::sleep(Duration::from_millis(2));
    };
    let by_op = |op: u64| acks.iter().find(|(o, _)| *o == op).unwrap().1.clone();
    assert_eq!(by_op(1), PersistOutcome::Persisted);
    assert_eq!(by_op(2), PersistOutcome::Persisted);
    assert!(matches!(by_op(3), PersistOutcome::Failed(msg) if msg.contains("UNIQUE")));

    let rows: i64 = db
        .read_blocking(|c| c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(rows, 2);
}

#[test]
fn a_full_pending_queue_refuses_before_writing() {
    let db = db();
    let executor = PersistExecutor::new(
        &db,
        PersistConfig {
            pending_capacity: 1,
            ..PersistConfig::default()
        },
        |effect: tesserax::swc::EffectEnvelope<i64>| {
            let n = effect.effect;
            Box::new(move |conn: &tesserax_store::rusqlite::Connection| {
                conn.execute("INSERT INTO t VALUES (?1)", [n])?;
                Ok(())
            })
        },
        |_, outcome| outcome,
    )
    .unwrap();
    let (handle, mut runtime) = Runtime::new(
        Core::new(Ledger::default()),
        RuntimeConfig::default(),
        executor,
    );
    for n in 10..20 {
        handle.dispatch(n).unwrap();
    }
    runtime.tick();
    let deadline = Instant::now() + Duration::from_secs(10);
    let acks = loop {
        runtime.tick();
        let acks = handle.snapshot().state.clone();
        if acks.len() == 10 {
            break acks;
        }
        assert!(Instant::now() < deadline, "{acks:?}");
        std::thread::sleep(Duration::from_millis(2));
    };
    let persisted = acks
        .iter()
        .filter(|(_, o)| *o == PersistOutcome::Persisted)
        .count() as i64;
    let refused = acks
        .iter()
        .filter(|(_, o)| matches!(o, PersistOutcome::Refused(_)))
        .count() as i64;
    assert!(persisted >= 1 && refused >= 1, "{acks:?}");
    assert_eq!(persisted + refused, 10);
    let rows: i64 = db
        .read_blocking(|c| c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(rows, persisted, "a refused effect wrote nothing");
}
