//! The window: a bar to open a stream and say where it comes from, the picture, and
//! what has arrived beside it.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align2, Color32, FontId, Id, Key, KeyboardShortcut, Modifiers, RichText, Sense, ViewportCommand, pos2, vec2,
};
use serde::{Deserialize, Serialize};

use crate::health::{self, Doing, Seen, Tone};
use crate::look;
use crate::network::{self, Network};
use crate::picture::Picture;
use crate::receiving::{Origin, Port, Run, Source, Stream, file_name, ports};
use st2110_discover::Found;

/// How many SDP files the app remembers opening.
const RECENT: usize = 8;

const OPEN: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::O);

/// The extensions of capture files; anything else dropped is taken for an SDP file.
const CAPTURES: [&str; 3] = ["pcap", "pcapng", "cap"];

/// What the app remembers between launches.
#[derive(Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Settings {
    /// The port to receive on, by name, or the one the system picks when `None`.
    pub(crate) port: Option<String>,
    /// SDP files opened, the newest first.
    pub(crate) recent: Vec<PathBuf>,
    /// Whether to find the streams on the network and list them.
    pub(crate) find: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { port: None, recent: Vec::new(), find: true }
    }
}

impl Settings {
    /// Puts `path` first among the files opened.
    fn opened(&mut self, path: &Path) {
        self.recent.retain(|p| p != path);
        self.recent.insert(0, path.to_path_buf());
        self.recent.truncate(RECENT);
    }
}

/// For testing that the app runs: closes the window once this many frames have
/// arrived, and says whether they arrived whole.
pub(crate) struct Check {
    pub(crate) frames: u64,
    /// Where to save a picture of the window before it closes.
    pub(crate) screenshot: Option<PathBuf>,
    pub(crate) passed: Rc<Cell<Option<bool>>>,
    /// The outcome, once known, while the picture of the window is awaited.
    outcome: Option<bool>,
    /// When the picture was asked for.
    asked: Option<Instant>,
}

impl Check {
    pub(crate) fn new(frames: u64, screenshot: Option<PathBuf>, passed: Rc<Cell<Option<bool>>>) -> Self {
        Self { frames, screenshot, passed, outcome: None, asked: None }
    }
}

/// What the command line asked for.
pub(crate) struct Start {
    pub(crate) sdp: Option<PathBuf>,
    pub(crate) pcap: Option<PathBuf>,
    pub(crate) check: Option<Check>,
}

pub(crate) struct Viewer {
    settings: Settings,
    /// The machine's ports, as they were when last listed.
    ports: Vec<Port>,
    stream: Option<Stream>,
    /// Whether to play a capture rather than receive from the network.
    from_capture: bool,
    capture: Option<PathBuf>,
    run: Option<Run>,
    /// Where the packets come from, to say so.
    from: String,
    started: Instant,
    /// Whether the person stopped receiving.
    stopped: bool,
    picture: Option<Picture>,
    seen: Seen,
    /// What went wrong last, until something else is started.
    error: Option<String>,
    check: Option<Check>,
    /// The streams found on the network, while they are listed.
    network: Option<Network>,
}

impl Viewer {
    pub(crate) fn new(cc: &eframe::CreationContext<'_>, start: Start) -> Self {
        look::apply(&cc.egui_ctx);
        // A test starts from nothing remembered.
        let settings = match (&start.check, cc.storage) {
            (None, Some(storage)) => eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default(),
            _ => Settings::default(),
        };
        let mut viewer = Self {
            settings,
            ports: ports(),
            stream: None,
            from_capture: start.pcap.is_some(),
            capture: start.pcap,
            run: None,
            from: String::new(),
            started: Instant::now(),
            stopped: false,
            picture: None,
            seen: Seen::default(),
            error: None,
            check: start.check,
            network: None,
        };
        if let Some(sdp) = start.sdp
            && viewer.load(&cc.egui_ctx, &sdp)
        {
            viewer.start(&cc.egui_ctx);
        }
        viewer
    }

    /// Reads an SDP file to receive its stream in place of the one open, or says why
    /// not and leaves that one be. Gives whether it did.
    fn load(&mut self, ctx: &egui::Context, path: &Path) -> bool {
        match Stream::open(path) {
            Ok(stream) => {
                self.settings.opened(path);
                self.show(ctx, stream);
                true
            }
            Err(e) => {
                self.error = Some(e);
                false
            }
        }
    }

    /// Opens a stream found on the network and receives it from the network, or says
    /// why not and leaves the one open be.
    fn load_found(&mut self, ctx: &egui::Context, found: &Found) {
        let Some(sdp) = &found.sdp else {
            return;
        };
        let origin = Origin::Network { name: found.name.clone(), by: network::by(found) };
        match Stream::read(sdp.clone(), origin) {
            Ok(stream) => {
                self.show(ctx, stream);
                self.from_capture = false;
                self.start(ctx);
            }
            Err(e) => self.error = Some(e),
        }
    }

    /// Puts a stream in place of the one open.
    fn show(&mut self, ctx: &egui::Context, stream: Stream) {
        self.halt();
        ctx.send_viewport_cmd(ViewportCommand::Title(format!("{} — ST 2110 Viewer", stream.name())));
        self.stream = Some(stream);
    }

    /// Saves the SDP file of the stream open, as found on the network.
    fn save_sdp(&mut self) {
        let Some(stream) = &self.stream else {
            return;
        };
        let name: String =
            stream.name().chars().map(|c| if c.is_alphanumeric() || " ._-()".contains(c) { c } else { '_' }).collect();
        let mut dialog = rfd::FileDialog::new()
            .set_title("Save the SDP file")
            .add_filter("SDP files", &["sdp"])
            .set_file_name(format!("{}.sdp", name.trim_matches([' ', '.'])));
        if let Some(folder) = self.settings.recent.first().and_then(|p| p.parent()) {
            dialog = dialog.set_directory(folder);
        }
        let Some(path) = dialog.save_file() else {
            return;
        };
        match std::fs::write(&path, &stream.sdp) {
            Ok(()) => self.settings.opened(&path),
            Err(e) => self.error = Some(format!("{}: {e}", file_name(&path))),
        }
    }

    /// Looks for streams on the network while they are listed, and stops when they are
    /// not. A test looks for none.
    fn discover(&mut self, ctx: &egui::Context) {
        if !self.settings.find || self.check.is_some() {
            self.network = None;
            return;
        }
        self.network.get_or_insert_with(|| Network::start(ctx)).update();
        // How long ago each announcement was heard moves on its own.
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    /// The streams found on the network, to pick one to play.
    fn network(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let current =
            self.stream.as_ref().filter(|s| matches!(s.origin, Origin::Network { .. })).map(|s| s.sdp.as_str());
        let picked = self.network.as_mut().and_then(|network| network.show(ui, current));
        if let Some(found) = picked {
            self.load_found(&ctx, &found);
        }
    }

    /// Starts receiving the open stream from where the bar says, in place of whatever
    /// was being received.
    fn start(&mut self, ctx: &egui::Context) {
        self.halt();
        if self.settings.port.is_some() {
            // Listed afresh, for the port's address may have changed.
            self.ports = ports();
        }
        let Some(stream) = &self.stream else {
            return;
        };
        // A fresh picture, so that what came before does not stand in for this.
        self.picture = stream.video.as_ref().map(|(f, _)| Picture::new(f.width as usize, f.height as usize));
        self.seen = Seen::default();
        let wake = {
            let ctx = ctx.clone();
            move || ctx.request_repaint()
        };
        match self.source().and_then(|(source, from)| Ok((Run::start(stream, &source, wake)?, from))) {
            Ok((run, from)) => {
                self.run = Some(run);
                (self.from, self.started, self.stopped, self.error) = (from, Instant::now(), false, None);
            }
            Err(e) => {
                self.run = None;
                self.error = Some(e);
            }
        }
    }

    /// Where the bar says the packets come from, and how to say so.
    fn source(&self) -> Result<(Source, String), String> {
        if self.from_capture {
            let path = self.capture.as_ref().ok_or("Choose a capture to play.")?;
            return Ok((Source::Capture(path.clone()), file_name(path)));
        }
        let Some(name) = &self.settings.port else {
            return Ok((Source::Network(None), "the port the system picks".into()));
        };
        match self.ports.iter().find(|p| &p.name == name) {
            Some(port) => Ok((Source::Network(Some(port.address)), format!("{} ({})", port.name, port.address))),
            None => Err(format!("The port {name} has no IPv4 address now; pick another.")),
        }
    }

    /// Stops receiving, and waits for it to end.
    fn halt(&mut self) {
        if let Some(run) = &mut self.run {
            run.stop();
        }
    }

    fn running(&mut self) -> bool {
        self.run.as_mut().is_some_and(Run::running)
    }

    /// Asks for an SDP file to open, and receives its stream.
    fn pick_sdp(&mut self, ctx: &egui::Context) {
        let folder = self.settings.recent.first().and_then(|p| p.parent()).map(Path::to_path_buf);
        if let Some(path) = pick("Open an SDP file", "SDP files", &["sdp"], folder)
            && self.load(ctx, &path)
        {
            self.start(ctx);
        }
    }

    /// Asks for a capture to play; gives whether one was chosen.
    fn pick_capture(&mut self) -> bool {
        let folder = self.capture.as_ref().or(self.settings.recent.first()).and_then(|p| p.parent());
        match pick("Play a capture", "Captures", &CAPTURES, folder.map(Path::to_path_buf)) {
            Some(path) => {
                self.capture = Some(path);
                true
            }
            None => false,
        }
    }

    /// Opens an SDP file dropped on the window, and plays a capture dropped with it or
    /// on its own.
    fn take_dropped(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).collect());
        if dropped.is_empty() {
            return;
        }
        let (captures, sdps): (Vec<PathBuf>, Vec<PathBuf>) = dropped.into_iter().partition(|p| is_capture(p));
        let loaded = sdps.first().is_some_and(|sdp| self.load(ctx, sdp));
        if let Some(capture) = captures.first() {
            (self.capture, self.from_capture) = (Some(capture.clone()), true);
        }
        if self.stream.is_none() {
            if !captures.is_empty() {
                self.error = Some("A capture plays with its stream's SDP file: drop both, or open that first.".into());
            }
        } else if loaded || !captures.is_empty() {
            self.start(ctx);
        }
    }

    /// Copies what has arrived, and unpacks the newest frame if it has yet to be shown.
    fn follow(&mut self, ctx: &egui::Context) {
        let Some(run) = &mut self.run else {
            return;
        };
        run.running();
        let mut latest = run.monitor.lock();
        let fresh = std::mem::take(&mut latest.fresh);
        if fresh && let Some(picture) = &mut self.picture {
            std::mem::swap(&mut latest.frame, &mut picture.frame);
        }
        self.seen = Seen::from(&latest, latest.last.map(|last| last.elapsed()));
        drop(latest);
        if let Some(Err(e)) = run.ended.take() {
            self.error = Some(e);
        }
        if fresh
            && let Some(picture) = &mut self.picture
            && let Some((_, converter)) = self.stream.as_ref().and_then(|s| s.video.as_ref())
        {
            picture.update(ctx, converter);
        }
    }

    /// The bar along the top: the SDP file, where the packets come from, and start and
    /// stop.
    fn bar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.horizontal_wrapped(|ui| {
            if self.check.is_none() {
                ui.toggle_value(&mut self.settings.find, "Find streams")
                    .on_hover_text("List the streams on the network, announced by SAP or published by NMOS");
                ui.separator();
            }
            let open = ui.button("Open SDP file…").on_hover_text(ctx.format_shortcut(&OPEN));
            if open.clicked() {
                self.pick_sdp(&ctx);
            }
            if !self.settings.recent.is_empty() {
                ui.menu_button("Recent", |ui| {
                    for path in self.settings.recent.clone() {
                        if ui.button(file_name(&path)).on_hover_text(path.display().to_string()).clicked() {
                            ui.close();
                            if self.load(&ctx, &path) {
                                self.start(&ctx);
                            }
                        }
                    }
                });
            }
            ui.separator();
            let mut restart = false;
            ui.label("From");
            restart |= ui.selectable_value(&mut self.from_capture, false, "Network").changed();
            let capture = ui.selectable_value(&mut self.from_capture, true, "Capture");
            // Choosing a capture is what the person is after.
            if capture.changed() {
                restart = self.capture.is_some() || self.pick_capture();
                self.from_capture = self.capture.is_some();
            }
            if self.from_capture {
                if ui.button("Choose…").clicked() && self.pick_capture() {
                    restart = true;
                }
                if let Some(path) = &self.capture {
                    ui.label(file_name(path)).on_hover_text(path.display().to_string());
                }
            } else {
                restart |= self.port_choice(ui);
            }
            ui.separator();
            if self.running() {
                if ui.button("Stop").clicked() {
                    self.halt();
                    self.stopped = true;
                }
            } else {
                let again = self.run.as_ref().is_some_and(|r| r.capture) && self.from_capture && !self.stopped;
                let label = if again { "Play again" } else { "Start" };
                restart |= ui.add_enabled(self.stream.is_some(), egui::Button::new(label)).clicked();
            }
            if restart && self.stream.is_some() {
                self.start(&ctx);
            }
        });
    }

    /// The port to receive on; gives whether the choice changed.
    fn port_choice(&mut self, ui: &mut egui::Ui) -> bool {
        let before = self.settings.port.clone();
        let selected = match &self.settings.port {
            None => "Any port".to_string(),
            Some(name) => self
                .ports
                .iter()
                .find(|p| &p.name == name)
                .map_or_else(|| format!("{name}, not connected"), Port::label),
        };
        ui.label("on");
        egui::ComboBox::from_id_salt("port").selected_text(selected).show_ui(ui, |ui| {
            // Listed afresh, for ports come and go.
            self.ports = ports();
            ui.selectable_value(&mut self.settings.port, None, "Any port")
                .on_hover_text("The port the system routes the stream's addresses to");
            for port in &self.ports {
                ui.selectable_value(&mut self.settings.port, Some(port.name.clone()), port.label());
            }
        });
        self.settings.port != before
    }

    /// The line along the bottom: what receiving is doing, and what went wrong.
    fn state_line(&mut self, ui: &mut egui::Ui) {
        let running = self.running();
        ui.horizontal_wrapped(|ui| {
            let said = match &self.run {
                Some(run) => {
                    let doing = Doing {
                        from: &self.from,
                        capture: run.capture,
                        running,
                        stopped: self.stopped,
                        since: self.started.elapsed(),
                    };
                    let (text, tone) = health::state(&doing, &self.seen);
                    ui.label(RichText::new(text).color(tone_color(ui, tone)));
                    true
                }
                None if self.stream.is_none() && self.error.is_none() => {
                    ui.weak(if self.network.is_some() {
                        "Pick a stream found on the network, or open an SDP file, to watch it."
                    } else {
                        "Open an SDP file to watch its stream."
                    });
                    true
                }
                None => false,
            };
            if let Some(error) = &self.error {
                if said {
                    ui.separator();
                }
                ui.label(RichText::new(error).color(ui.visuals().error_fg_color));
            }
        });
    }

    /// The panel beside the picture: the stream, and what has arrived.
    fn panel(&mut self, ui: &mut egui::Ui) {
        let Some(stream) = &self.stream else {
            return;
        };
        let mut save = false;
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(4.0);
            let (name, format) = (stream.name(), stream.format());
            ui.heading(&name);
            // Senders often name a stream by its format, as `st2110 send` does.
            if !name.contains(&format) {
                ui.label(format);
            }
            let legs = &stream.description.legs;
            for (i, leg) in legs.iter().enumerate() {
                let label = if legs.len() > 1 { format!("Leg {}: {leg}", i + 1) } else { leg.to_string() };
                ui.weak(label);
            }
            if let Origin::Network { by, .. } = &stream.origin {
                ui.weak(format!("Found by {by}"));
                save = ui.small_button("Save SDP file…").clicked();
            }
            ui.separator();
            egui::Grid::new("arrived").num_columns(2).striped(true).spacing([12.0, 4.0]).show(ui, |ui| {
                for row in health::rows(&self.seen) {
                    ui.label(row.label);
                    ui.label(RichText::new(row.value).color(tone_color(ui, row.tone)));
                    ui.end_row();
                }
            });
            let report = self.seen.report.as_ref();
            let problems = report.map_or(&[][..], |r| &r.problems[..]);
            if !problems.is_empty() {
                ui.add_space(8.0);
                ui.strong("Problems");
                for problem in problems {
                    ui.label(RichText::new(problem).color(ui.visuals().error_fg_color));
                }
            }
            let warnings = self.run.as_ref().map_or(&[][..], |r| &r.warnings[..]);
            let notes = report.map_or(&[][..], |r| &r.notes[..]);
            if !(warnings.is_empty() && stream.notes.is_empty() && notes.is_empty()) {
                ui.add_space(8.0);
                ui.strong("Notes");
                for note in warnings {
                    ui.label(RichText::new(note).color(ui.visuals().warn_fg_color));
                }
                for note in stream.notes.iter().chain(notes) {
                    ui.weak(note);
                }
            }
        });
        if save {
            self.save_sdp();
        }
    }

    /// The picture, or what to do to see one, on black.
    fn screen(&mut self, ui: &mut egui::Ui, fullscreen: bool) {
        let ctx = ui.ctx().clone();
        let space = ui.max_rect();
        let painter = ui.painter().clone();
        painter.rect_filled(space, 0.0, look::CANVAS);
        let middle = space.center();
        let big = FontId::proportional(20.0);
        let small = FontId::proportional(14.0);
        match (&self.stream, &self.picture) {
            (None, _) => {
                let (title, hint) = if self.network.is_some() {
                    (
                        "Pick a stream found on the network",
                        "or open an SDP file, or drop one here, with a capture to play it.",
                    )
                } else {
                    ("Open an SDP file", "or drop one here. A capture plays with its stream's SDP file: drop both.")
                };
                painter.text(middle - vec2(0.0, 40.0), Align2::CENTER_CENTER, title, big, look::ON_CANVAS);
                painter.text(middle - vec2(0.0, 12.0), Align2::CENTER_CENTER, hint, small, look::ON_CANVAS_WEAK);
                let button = egui::Rect::from_center_size(middle + vec2(0.0, 24.0), vec2(140.0, 28.0));
                if ui.put(button, egui::Button::new("Open SDP file…")).clicked() {
                    self.pick_sdp(&ctx);
                }
            }
            (Some(stream), _) if stream.video.is_none() => {
                let text = format!("Audio: {}", stream.format());
                painter.text(middle - vec2(0.0, 12.0), Align2::CENTER_CENTER, text, big, look::ON_CANVAS);
                let hint = "No picture to show. What arrives is counted beside it, with each channel's loudest sample.";
                painter.text(middle + vec2(0.0, 16.0), Align2::CENTER_CENTER, hint, small, look::ON_CANVAS_WEAK);
            }
            (Some(_), None) => {}
            (Some(_), Some(picture)) => {
                let at = picture.paint(&painter, space);
                let running = self.run.as_mut().is_some_and(Run::running);
                if !picture.shown() {
                    let text = if running { "Waiting for the first frame" } else { "No frame arrived" };
                    painter.text(middle, Align2::CENTER_CENTER, text, big, look::ON_CANVAS);
                } else if running && let Some(quiet) = self.seen.quiet.filter(|q| *q >= Duration::from_secs(1)) {
                    let text = format!("Nothing for {} s", quiet.as_secs());
                    let corner = pos2(at.min.x.max(space.min.x) + 12.0, at.min.y.max(space.min.y) + 12.0);
                    let galley = painter.layout_no_wrap(text, big, look::ON_CANVAS_WARN);
                    let badge = egui::Rect::from_min_size(corner, galley.size()).expand(6.0);
                    painter.rect_filled(badge, 4.0, Color32::from_black_alpha(190));
                    painter.galley(corner, galley, look::ON_CANVAS_WARN);
                }
                // Double-click for the picture alone, filling the screen.
                let response = ui.interact(space, Id::new("picture"), Sense::click());
                if response.double_clicked() {
                    ctx.send_viewport_cmd(ViewportCommand::Fullscreen(!fullscreen));
                }
            }
        }
        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            painter.rect_filled(space, 0.0, look::VEIL);
            let text = "Drop an SDP file to open it, or a capture to play it";
            painter.text(middle, Align2::CENTER_CENTER, text, FontId::proportional(20.0), look::ON_CANVAS);
        }
    }

    /// For a test, closes the window once enough frames have arrived or receiving has
    /// ended without them, and says which; first saves a picture of the window, if
    /// asked to.
    fn check(&mut self, ctx: &egui::Context) {
        let running = self.running();
        let Some(check) = &mut self.check else {
            return;
        };
        if check.passed.get().is_some() {
            return;
        }
        if check.outcome.is_none() {
            let seen = &self.seen;
            let (passed, said) = if seen.frames >= check.frames {
                let from = if self.from.is_empty() { String::new() } else { format!(" from {}", self.from) };
                let said = format!("{} frames arrived{from}, {} incomplete", seen.frames, seen.incomplete);
                (seen.incomplete == 0 && seen.whole, said)
            } else if !running {
                (false, self.error.clone().unwrap_or_else(|| format!("only {} frames arrived", seen.frames)))
            } else {
                return;
            };
            println!("st2110-viewer: {said}");
            for problem in seen.report.iter().flat_map(|r| &r.problems) {
                println!("st2110-viewer: problem: {problem}");
            }
            check.outcome = Some(passed);
            if check.screenshot.is_some() {
                ctx.send_viewport_cmd(ViewportCommand::Screenshot(egui::UserData::default()));
                check.asked = Some(Instant::now());
            }
        }
        if let Some(path) = &check.screenshot {
            let image = ctx.input(|i| {
                i.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            match image {
                Some(image) => match save_png(path, &image) {
                    Ok(()) => println!("st2110-viewer: saved a picture of the window to {}", path.display()),
                    Err(e) => {
                        eprintln!("st2110-viewer: {}: {e}", path.display());
                        check.outcome = Some(false);
                    }
                },
                // It comes with a frame drawn after the one that asked for it.
                None if check.asked.is_some_and(|at| at.elapsed() < Duration::from_secs(10)) => {
                    ctx.request_repaint();
                    return;
                }
                None => {
                    eprintln!("st2110-viewer: no picture of the window came, so {} was not saved", path.display());
                    check.outcome = Some(false);
                }
            }
        }
        check.passed.set(check.outcome);
        ctx.send_viewport_cmd(ViewportCommand::Close);
    }
}

impl eframe::App for Viewer {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.take_dropped(&ctx);
        if ctx.input_mut(|i| i.consume_shortcut(&OPEN)) {
            self.pick_sdp(&ctx);
        }
        self.follow(&ctx);
        self.discover(&ctx);
        let fullscreen = ctx.input(|i| i.viewport().fullscreen.unwrap_or(false));
        if fullscreen && ctx.input(|i| i.key_pressed(Key::Escape)) {
            ctx.send_viewport_cmd(ViewportCommand::Fullscreen(false));
        }
        if !fullscreen {
            egui::Panel::top("bar").show(ui, |ui| self.bar(ui));
            egui::Panel::bottom("state").show(ui, |ui| self.state_line(ui));
            if self.network.is_some() {
                egui::Panel::left("network").resizable(true).default_size(280.0).min_size(200.0).show(ui, |ui| {
                    self.network(ui);
                });
            }
            if self.stream.is_some() {
                egui::Panel::right("arrived").resizable(true).default_size(320.0).min_size(220.0).show(ui, |ui| {
                    self.panel(ui);
                });
            }
        }
        egui::CentralPanel::no_frame().show(ui, |ui| self.screen(ui, fullscreen));
        self.check(&ctx);
        // Counts that move without a frame arriving, such as how long nothing has.
        if self.running() {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        if self.check.is_none() {
            eframe::set_value(storage, eframe::APP_KEY, &self.settings);
        }
    }

    fn on_exit(&mut self) {
        self.halt();
    }
}

/// The colour for a row or line of `tone`.
fn tone_color(ui: &egui::Ui, tone: Tone) -> Color32 {
    match tone {
        Tone::Plain => ui.visuals().text_color(),
        Tone::Warn => ui.visuals().warn_fg_color,
        Tone::Bad => ui.visuals().error_fg_color,
    }
}

/// Whether a file is a capture, by its extension.
fn is_capture(path: &Path) -> bool {
    path.extension().is_some_and(|e| CAPTURES.iter().any(|c| e.eq_ignore_ascii_case(c)))
}

/// Saves a picture of the window as a PNG file.
fn save_png(path: &Path, image: &egui::ColorImage) -> std::io::Result<()> {
    let [width, height] = image.size;
    // Opaque, so its premultiplied colours are the colours.
    let rgb: Vec<u8> = image.pixels.iter().flat_map(|p| [p.r(), p.g(), p.b()]).collect();
    let mut out = std::io::BufWriter::new(std::fs::File::create(path)?);
    st2110_media::files::write_png(&mut out, width as u32, height as u32, &rgb)?;
    std::io::Write::flush(&mut out)
}

/// Asks for a file of one kind, starting in `folder`.
fn pick(title: &str, kind: &str, extensions: &[&str], folder: Option<PathBuf>) -> Option<PathBuf> {
    let mut dialog = rfd::FileDialog::new().set_title(title).add_filter(kind, extensions);
    if let Some(folder) = folder {
        dialog = dialog.set_directory(folder);
    }
    dialog.pick_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_the_files_opened_newest_first() {
        let mut settings = Settings::default();
        for i in 0..10 {
            settings.opened(Path::new(&format!("/streams/{i}.sdp")));
        }
        settings.opened(Path::new("/streams/4.sdp"));
        let names: Vec<String> = settings.recent.iter().map(|p| file_name(p)).collect();
        assert_eq!(names, ["4.sdp", "9.sdp", "8.sdp", "7.sdp", "6.sdp", "5.sdp", "3.sdp", "2.sdp"]);
    }

    #[test]
    fn tells_captures_by_their_extension() {
        assert!(is_capture(Path::new("/tmp/bars.pcap")) && is_capture(Path::new("B.PCAPNG")));
        assert!(!is_capture(Path::new("bars.sdp")) && !is_capture(Path::new("pcap")));
    }
}
