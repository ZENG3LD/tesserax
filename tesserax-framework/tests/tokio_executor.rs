//! Feature `tokio`: effects as tasks; answers, panics and the in-flight
//! bound all come back as observations.
#![cfg(feature = "tokio")]

mod common;

use std::time::{Duration, Instant};

use common::{Cmd, Jobs, Obs, Status, Work};
use tesserax::swc::{EffectEnvelope, Port};
use tesserax_framework::{
    Core, EffectTicket, Refusal, Runtime, RuntimeConfig, TokioExecutor, TokioExecutorConfig,
};

fn refuse(_: EffectTicket, why: Refusal) -> Obs {
    Obs::Refused(why.to_string())
}

#[test]
fn tokio_tasks_answer_effects() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_time()
        .build()
        .unwrap();
    let executor = TokioExecutor::new(
        rt.handle().clone(),
        TokioExecutorConfig {
            max_in_flight: 2,
            ..TokioExecutorConfig::default()
        },
        |effect: EffectEnvelope<Work>| async move {
            match effect.effect.input {
                0 => panic!("boom"),
                n if n >= 100 => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Obs::Done(n)
                }
                n => Obs::Done(n * 2),
            }
        },
        refuse,
    );
    let (handle, mut runtime) = Runtime::new(
        Core::new(Jobs::default()),
        RuntimeConfig::default(),
        executor,
    );
    for s in 1..=4 {
        handle.dispatch(Cmd::Create(s)).unwrap();
    }
    // Two slow ones fill the in-flight bound; the third is refused.
    handle.dispatch(Cmd::Start(1, 100)).unwrap();
    handle.dispatch(Cmd::Start(2, 100)).unwrap();
    handle.dispatch(Cmd::Start(3, 5)).unwrap();
    runtime.tick();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        runtime.tick();
        let jobs = handle.snapshot().state.jobs.clone();
        if jobs[&1].status == Status::Done(100) && jobs[&2].status == Status::Done(100) {
            assert_eq!(
                jobs[&3].status,
                Status::Refused("executor is full".to_owned())
            );
            break;
        }
        assert!(Instant::now() < deadline, "{jobs:?}");
        std::thread::sleep(Duration::from_millis(2));
    }
    // A panic in the work is answered as a refusal.
    handle.dispatch(Cmd::Start(4, 0)).unwrap();
    loop {
        runtime.tick();
        if handle.snapshot().state.jobs[&4].status
            == Status::Refused("effect work panicked".to_owned())
        {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
}
