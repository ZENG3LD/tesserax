//! A toy domain for the kernel and runtime tests: jobs that run one piece
//! of work each, recreated under a new generation.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use tesserax::swc::{
    CommandId, Generation, ObservationEnvelope, OperationId, Reject, RejectCode, Subject,
};
use tesserax_framework::{Domain, Tick};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmd {
    /// Create the job, or recreate it under the next generation.
    Create(u64),
    /// Run one piece of work for the job.
    Start(u64, u64),
    /// Emit `Pong`, touch nothing else.
    Ping,
    /// Request an effect and emit an event, then refuse.
    Fail,
    /// Record a label in the phase log only.
    Mark(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Work {
    pub input: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Obs {
    Done(u64),
    Refused(String),
    /// An unsolicited fact.
    Note(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ev {
    Created { generation: u64 },
    Started { operation: u64 },
    Finished { output: u64 },
    Refused(String),
    Note(&'static str),
    Pong,
    Doomed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Idle,
    Running(OperationId),
    Done(u64),
    Refused(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub generation: Generation,
    pub status: Status,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub jobs: BTreeMap<u64, Job>,
    pub notes: Vec<&'static str>,
}

#[derive(Default)]
pub struct Jobs {
    state: State,
    /// Every reducer call, in order (the phase-order record).
    pub log: RefCell<Vec<String>>,
}

impl Jobs {
    pub fn take_log(&self) -> Vec<String> {
        std::mem::take(&mut *self.log.borrow_mut())
    }

    fn record(&self, entry: String) {
        self.log.borrow_mut().push(entry);
    }
}

impl Domain for Jobs {
    type Command = Cmd;
    type Effect = Work;
    type Observation = Obs;
    type Event = Ev;
    type State = State;

    fn advance(&mut self, tick: &mut Tick<'_, Self>) {
        self.record(format!("advance:{}", tick.now()));
    }

    fn apply_command(
        &mut self,
        tick: &mut Tick<'_, Self>,
        id: CommandId,
        command: Cmd,
    ) -> Result<(), Reject> {
        self.record(format!("command:{command:?}"));
        match command {
            Cmd::Create(s) => {
                let generation = match self.state.jobs.get(&s) {
                    Some(job) => Generation(job.generation.0 + 1),
                    None => Generation(1),
                };
                self.state.jobs.insert(
                    s,
                    Job {
                        generation,
                        status: Status::Idle,
                    },
                );
                tick.emit(
                    Some(id),
                    Some(Subject(s)),
                    generation,
                    Ev::Created {
                        generation: generation.0,
                    },
                )?;
            }
            Cmd::Start(s, input) => {
                let job = self
                    .state
                    .jobs
                    .get(&s)
                    .ok_or_else(|| Reject::new(RejectCode::Invalid, "no such job"))?;
                let generation = job.generation;
                let op = tick.effect(Some(Subject(s)), generation, Work { input })?;
                tick.emit(
                    Some(id),
                    Some(Subject(s)),
                    generation,
                    Ev::Started { operation: op.0 },
                )?;
                if let Some(job) = self.state.jobs.get_mut(&s) {
                    job.status = Status::Running(op);
                }
            }
            Cmd::Ping => tick.emit(Some(id), None, Generation::default(), Ev::Pong)?,
            Cmd::Fail => {
                tick.effect(None, Generation::default(), Work { input: 0 })?;
                tick.emit(Some(id), None, Generation::default(), Ev::Doomed)?;
                return Err(Reject::new(RejectCode::Domain(7), "refused on purpose"));
            }
            Cmd::Mark(_) => {}
        }
        Ok(())
    }

    fn generation_of(&self, subject: Subject) -> Option<Generation> {
        self.state.jobs.get(&subject.0).map(|job| job.generation)
    }

    fn apply_observation(&mut self, tick: &mut Tick<'_, Self>, o: ObservationEnvelope<Obs>) {
        self.record(format!(
            "observation:{}:{:?}",
            o.operation_id.map_or(0, |op| op.0),
            o.observation
        ));
        let event = match o.observation {
            Obs::Done(output) => {
                if let Some(job) = o.subject.and_then(|s| self.state.jobs.get_mut(&s.0)) {
                    job.status = Status::Done(output);
                }
                Ev::Finished { output }
            }
            Obs::Refused(why) => {
                if let Some(job) = o.subject.and_then(|s| self.state.jobs.get_mut(&s.0)) {
                    job.status = Status::Refused(why.clone());
                }
                Ev::Refused(why)
            }
            Obs::Note(note) => {
                self.state.notes.push(note);
                Ev::Note(note)
            }
        };
        let _ = tick.emit(None, o.subject, o.generation, event);
    }

    fn project(&self) -> State {
        self.record("project".to_owned());
        self.state.clone()
    }
}

/// The observation the toy executor produces: output = input * 2.
pub fn work(effect: tesserax::swc::EffectEnvelope<Work>) -> Obs {
    Obs::Done(effect.effect.input * 2)
}
