//! The streams on the network, found by SAP and NMOS as `st2110 discover` finds them,
//! listed beside the picture to pick one to play.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText, Sense};
use st2110_discover::nmos::ApiKind;
use st2110_discover::{Discovery, Found, List, Options, Origin};

use crate::look;
use crate::receiving::Stream;
use crate::tokens::{radius, space, timing};

/// What to run to send a stream to find, with no other kit.
const TRY: &str = "st2110 send video 720p50 --to 239.10.1.1:5004 --clock traceable --sap";

/// Inside a stream's row: the 4px grid, wider than it is tall.
const ROW_MARGIN: egui::Margin = egui::Margin::symmetric(space::STEP_2 as i8, space::STEP_1 as i8);

/// How long reading takes before the list shows it is busy: a spinner that
/// flashes for less is noise (the design system's timing.wait).
const WAIT: Duration = Duration::from_millis(timing::WAIT as u64);

/// How long the list says it is looking before it says it has found nothing.
const LOOKING: Duration = Duration::from_secs(3);

/// A stream found, and what playing it would show: its format, or why it cannot be
/// played.
pub(crate) struct Listed {
    pub(crate) found: Found,
    pub(crate) playable: Result<String, String>,
}

/// Looks for streams on every port while the list is shown.
pub(crate) struct Network {
    discovery: Discovery,
    started: Instant,
    /// The list as last read, its streams in `listed`.
    list: List,
    listed: Vec<Listed>,
    /// The discovery's generation when the list was read, and when.
    read: Option<(u64, Instant)>,
    /// What each SDP file found would play as, by its text: kept, as the list is read
    /// again every second.
    playable: HashMap<String, Result<String, String>>,
    /// Since when the NMOS Senders have been being read, while they are.
    busy_since: Option<Instant>,
}

impl Network {
    /// Starts looking, waking the window whenever the list changes.
    pub(crate) fn start(ctx: &egui::Context) -> Self {
        let ctx = ctx.clone();
        Self {
            discovery: Discovery::start(Options::default(), move || ctx.request_repaint()),
            started: Instant::now(),
            list: List::default(),
            listed: Vec::new(),
            read: None,
            playable: HashMap::new(),
            busy_since: None,
        }
    }

    /// Reads the list again when it has changed, and every second for how long ago each
    /// announcement was heard.
    pub(crate) fn update(&mut self) {
        let generation = self.discovery.generation();
        if self.read.is_some_and(|(g, at)| g == generation && at.elapsed() < Duration::from_secs(1)) {
            return;
        }
        self.read = Some((generation, Instant::now()));
        let mut list = self.discovery.list();
        let mut playable = std::mem::take(&mut self.playable);
        self.listed = std::mem::take(&mut list.streams)
            .into_iter()
            .map(|found| {
                let result = match &found.sdp {
                    Some(text) => {
                        let result = playable.remove(text).unwrap_or_else(|| Stream::playable(text));
                        self.playable.insert(text.clone(), result.clone());
                        result
                    }
                    None => Err(found.problem.clone().unwrap_or_else(|| "it has no SDP file".into())),
                };
                Listed { found, playable: result }
            })
            .collect();
        self.list = list;
    }

    /// Asks again at once, and reads every SDP file again.
    pub(crate) fn refresh(&mut self) {
        self.discovery.refresh();
        self.playable.clear();
        self.read = None;
    }

    /// The list, with the stream whose SDP file is `current` marked; gives the stream
    /// picked to play, if one was.
    pub(crate) fn show(&mut self, ui: &mut egui::Ui, current: Option<&str>) -> Option<Found> {
        let mut picked = None;
        ui.horizontal(|ui| {
            ui.strong("On the network");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let refresh =
                    look::small_button(ui, "Refresh").on_hover_text("Ask again, and read every SDP file again");
                if refresh.clicked() {
                    self.refresh();
                }
                // Busy shows once the reading has taken timing.wait, not at once.
                if self.list.busy {
                    let since = *self.busy_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= WAIT {
                        ui.spinner().on_hover_text("Reading the NMOS Senders");
                    } else {
                        ui.ctx().request_repaint_after(WAIT.saturating_sub(since.elapsed()));
                    }
                } else {
                    self.busy_since = None;
                }
            });
        });
        ui.separator();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if self.listed.is_empty() {
                self.nothing(ui);
            }
            for (i, listed) in self.listed.iter().enumerate() {
                let marked = current.is_some() && listed.found.sdp.as_deref() == current;
                if row(ui, i, listed, marked).clicked() && listed.playable.is_ok() {
                    picked = Some(listed.found.clone());
                }
            }
            ui.add_space(8.0);
            self.footer(ui);
        });
        picked
    }

    /// What to say while nothing has been found.
    fn nothing(&self, ui: &mut egui::Ui) {
        if self.started.elapsed() < LOOKING {
            ui.weak("Looking…");
            return;
        }
        ui.label("No streams found yet.");
        ui.add_space(4.0);
        let how = "Senders that announce by SAP appear within 30 seconds or so, and NMOS Senders once a \
                   registry or a Node answers.";
        ui.weak(how);
        ui.add_space(6.0);
        ui.label("To try it with the st2110 command-line tool, send one:");
        ui.label(RichText::new(TRY).monospace());
        if look::small_button(ui, "Copy").clicked() {
            ui.ctx().copy_text(TRY.into());
        }
        ui.add_space(8.0);
    }

    /// Where the NMOS Senders came from, where it looks, and what went wrong.
    fn footer(&self, ui: &mut egui::Ui) {
        let nodes = self.list.apis.iter().filter(|a| a.kind == ApiKind::Node).count();
        let nmos = match (&self.list.registry, self.list.peer_to_peer) {
            (Some(registry), _) => format!("NMOS Senders from the registry at {registry}"),
            (None, true) => format!("NMOS Senders from {} peer to peer", plural(nodes, "Node")),
            (None, false) => "No NMOS registry or Node has answered.".into(),
        };
        ui.weak(nmos);
        ui.weak("Where it looks").on_hover_text(self.list.looking.join("\n"));
        for note in &self.list.notes {
            ui.colored_label(ui.visuals().warn_fg_color, note);
        }
    }
}

/// One stream in the list, which plays when clicked if it can.
fn row(ui: &mut egui::Ui, i: usize, listed: &Listed, marked: bool) -> egui::Response {
    let found = &listed.found;
    let background = ui.painter().add(egui::Shape::Noop);
    let inner = egui::Frame::new().inner_margin(ROW_MARGIN).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.spacing_mut().item_spacing.y = 1.0;
        let dim = listed.playable.is_err() || found.stale || found.active == Some(false);
        let name = RichText::new(&found.name);
        ui.label(if dim { name.color(ui.visuals().weak_text_color()) } else { name.strong() });
        let format = listed.playable.clone().unwrap_or_else(|_| found.format());
        let destinations = found.destinations();
        for line in
            [format, if destinations.is_empty() { String::new() } else { format!("to {}", destinations.join(" and ")) }]
        {
            if !line.is_empty() {
                ui.weak(line);
            }
        }
        let warn = ui.visuals().warn_fg_color;
        let state = match &listed.playable {
            Err(why) => Some(format!("Cannot play: {why}")),
            Ok(_) if found.active == Some(false) => Some("Not sending".into()),
            Ok(_) if found.stale => found.by.iter().find_map(|o| match o {
                Origin::Sap { heard_s, .. } => Some(format!("Not heard for {}: it may have stopped", ago(*heard_s))),
                Origin::Nmos { .. } => None,
            }),
            Ok(_) => None,
        };
        if let Some(state) = state {
            ui.label(RichText::new(state).color(warn));
        }
    });
    let rect = inner.response.rect;
    let response = ui.interact(rect, ui.id().with(("found", i)), Sense::click());
    let fill = if marked {
        ui.visuals().selection.bg_fill
    } else if response.hovered() && listed.playable.is_ok() {
        ui.visuals().widgets.hovered.weak_bg_fill
    } else {
        Color32::TRANSPARENT
    };
    ui.painter().set(background, egui::Shape::rect_filled(rect, radius::regular::CONTROL, fill));
    // The selection is the accent's wash with a bar at its start, as a list's row is.
    if marked {
        let bar = egui::Rect::from_min_size(rect.min, egui::vec2(space::HALF, rect.height()));
        ui.painter().rect_filled(bar, 0.0, ui.visuals().selection.stroke.color);
    }
    let mut hover = vec![by(found)];
    hover.extend(found.problem.iter().map(|p| format!("No SDP file: {p}")));
    if listed.playable.is_ok() && !marked {
        hover.push("Click to play it.".into());
    }
    response.on_hover_text(hover.join("\n"))
}

/// How a stream was found, in a line: `NMOS Node Camera 1; SAP from 192.168.10.21`.
pub(crate) fn by(found: &Found) -> String {
    let by: Vec<String> = found
        .by
        .iter()
        .map(|origin| match origin {
            Origin::Sap { interval_s: Some(every), .. } => format!("{}, every {every:.0} s", origin.describe()),
            _ => origin.describe(),
        })
        .collect();
    by.join("; ")
}

/// A time gone by, in seconds or minutes.
fn ago(seconds: f64) -> String {
    if seconds < 120.0 { format!("{seconds:.0} s") } else { format!("{:.0} min", seconds / 60.0) }
}

fn plural(count: usize, noun: &str) -> String {
    if count == 1 { format!("1 {noun}") } else { format!("{count} {noun}s") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn says_how_long_ago_and_how_a_stream_was_found() {
        assert_eq!((ago(95.4), ago(150.0)), ("95 s".to_string(), "2 min".to_string()));
        let found = Found {
            name: "CAM 1 video".into(),
            id: "nmos 5e0d0001".into(),
            sdp: None,
            streams: Vec::new(),
            active: Some(true),
            stale: false,
            problem: None,
            by: vec![
                Origin::Nmos {
                    id: "5e0d0001".into(),
                    label: "CAM 1 video".into(),
                    node: Some("Camera 1".into()),
                    device: None,
                    api: "http://192.168.10.21/x-nmos/node/v1.3/".into(),
                    peer_to_peer: true,
                },
                Origin::Sap { announcer: [192, 168, 10, 21].into(), heard_s: 4.0, interval_s: Some(30.0) },
            ],
        };
        assert_eq!(by(&found), "NMOS Node Camera 1; SAP from 192.168.10.21, every 30 s");
    }
}
