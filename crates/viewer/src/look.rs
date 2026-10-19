//! How the window looks: egui's visuals built from the shared design system's roles
//! (legofsalmon/design-system, vendored as `tokens.rs`), in both themes, spaced at
//! its regular density. The app follows the system's theme, as it did on egui's own
//! visuals.
//!
//! The type stays egui's own faces, sized by the design system's text styles: IBM
//! Plex is the system's face, and egui reads font files, not the system's fonts, so
//! taking it means bundling the files, which waits for the design system to ship
//! them.

use eframe::egui::{self, Color32, CornerRadius, FontId, Margin, Shadow, Stroke, TextStyle, Theme, vec2};

use crate::tokens::{color, elevation, motion, radius, size, space, text, timing};

/// A colour from the design system, as egui takes it.
const fn rgba(c: crate::tokens::Rgba) -> Color32 {
    Color32::from_rgba_unmultiplied_const(c.r, c.g, c.b, c.a)
}

/// Text on the black around the picture, which is dark in both themes.
pub(crate) const ON_CANVAS: Color32 = rgba(color::dark::ink::ON_CANVAS);
/// Hints on the black around the picture.
pub(crate) const ON_CANVAS_WEAK: Color32 = rgba(color::dark::ink::SECONDARY);
/// Around the picture, in both themes.
pub(crate) const CANVAS: Color32 = rgba(color::dark::surface::CANVAS);
/// Something on the picture that needs a look: nothing has arrived for a while.
pub(crate) const ON_CANVAS_WARN: Color32 = rgba(color::dark::warn::INK);

/// Behind what is laid over the picture: a file being dropped on it.
pub(crate) const VEIL: Color32 = rgba(color::dark::VEIL);
/// Behind words laid on the picture itself, which can be any colour: the canvas,
/// three quarters opaque, so the warning ink keeps its contrast over white. The
/// design system has no role for this yet; the veil is too light for it.
pub(crate) const SCRIM: Color32 = {
    let c = color::dark::surface::CANVAS;
    Color32::from_rgba_unmultiplied_const(c.r, c.g, c.b, 190)
};

/// Text over the picture: a line that says what to do, and its hint.
pub(crate) const ON_CANVAS_TITLE: f32 = text::regular::HEADING.size;
pub(crate) const ON_CANVAS_HINT: f32 = text::regular::PROSE.size;

/// Sets the visuals for both themes, the sizes, and the motion.
pub(crate) fn apply(ctx: &egui::Context) {
    ctx.set_visuals_of(Theme::Dark, dark());
    ctx.set_visuals_of(Theme::Light, light());
    let motion = Motion::asked();
    ctx.all_styles_mut(|style| {
        regular(style);
        motion.apply(style);
    });
}

/// How much the window moves: the design system's full motion, or reduced, which
/// removes movement and keeps the fades, shorter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Motion {
    Full,
    Reduced,
}

impl Motion {
    /// The motion this machine asked for, read once. `ST2110_MOTION=reduced` (or
    /// `full`) decides, for a show machine short of GPU or a screen recording;
    /// otherwise the Mac's Reduce motion setting does; otherwise full.
    pub(crate) fn asked() -> Self {
        static ASKED: std::sync::OnceLock<Motion> = std::sync::OnceLock::new();
        *ASKED.get_or_init(|| Self::from(std::env::var("ST2110_MOTION").ok().as_deref(), os_reduces_motion))
    }

    fn from(setting: Option<&str>, os_reduces: impl FnOnce() -> bool) -> Self {
        match setting {
            Some("reduced") => Self::Reduced,
            Some("full") => Self::Full,
            _ if os_reduces() => Self::Reduced,
            _ => Self::Full,
        }
    }

    /// Seconds for a small thing arriving near where it was asked for: a menu, the
    /// port list, a fold.
    fn base(self) -> f32 {
        let ms = match self {
            Self::Full => motion::full::duration::BASE,
            Self::Reduced => motion::reduced::duration::BASE,
        };
        ms as f32 / 1000.0
    }

    fn apply(self, style: &mut egui::Style) {
        // egui's menus, popups and folds open over animation_time.
        style.animation_time = self.base();
        // A list scrolled by a wheel or a key glides there; under reduced motion it
        // jumps, as nothing travels.
        if self == Self::Reduced {
            style.scroll_animation = egui::style::ScrollAnimation::none();
        }
        // Not animation: how long the pointer rests before a hover says what a
        // control does. It never changes with motion.
        style.interaction.tooltip_delay = timing::TOOLTIP as f32 / 1000.0;
    }
}

#[cfg(target_os = "macos")]
fn os_reduces_motion() -> bool {
    std::process::Command::new("defaults")
        .args(["read", "com.apple.universalaccess", "reduceMotion"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "1")
}

#[cfg(not(target_os = "macos"))]
fn os_reduces_motion() -> bool {
    false
}

/// The regular density: 32px controls and rows, 12px either side of a button's
/// label, the 4px grid between things, and the text styles' sizes.
fn regular(style: &mut egui::Style) {
    let s = &mut style.spacing;
    // A button, a menu and a choice are the control height; so is a row of the grid.
    s.interact_size = vec2(space::STEP_10, size::regular::CONTROL);
    s.button_padding = vec2(size::regular::CONTROL_PADDING, space::STEP_1);
    s.item_spacing = vec2(space::STEP_2, space::STEP_1);
    s.window_margin = Margin::same(space::STEP_2 as i8);
    s.menu_margin = Margin::same(space::STEP_2 as i8);
    let t = &mut style.text_styles;
    t.insert(TextStyle::Small, FontId::proportional(text::regular::CAPTION.size));
    t.insert(TextStyle::Body, FontId::proportional(text::regular::BODY.size));
    t.insert(TextStyle::Button, FontId::proportional(text::regular::CONTROL.size));
    t.insert(TextStyle::Heading, FontId::proportional(text::regular::TITLE.size));
    t.insert(TextStyle::Monospace, FontId::monospace(text::regular::CODE.size));
}

/// A button in a line of text or a panel's head: the small control's height, which
/// is also the smallest anything is to hit (egui's own small button is the text's
/// height).
pub(crate) fn small_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(egui::Button::new(label).small().min_size(vec2(0.0, size::regular::CONTROL_SM)))
}

/// One theme's roles, as the visuals need them.
struct Roles {
    ground: Color32,
    panel: Color32,
    inset: Color32,
    raised: Color32,
    raised_hover: Color32,
    overlay: Color32,
    primary: Color32,
    secondary: Color32,
    subtle: Color32,
    strong: Color32,
    control: Color32,
    accent_ink: Color32,
    accent_soft: Color32,
    focus: Color32,
    warn: Color32,
    bad: Color32,
    menu: crate::tokens::Shadow,
    modal: crate::tokens::Shadow,
}

fn dark() -> egui::Visuals {
    use color::dark as c;
    visuals(
        egui::Visuals::dark(),
        &Roles {
            ground: rgba(c::surface::GROUND),
            panel: rgba(c::surface::PANEL),
            inset: rgba(c::surface::INSET),
            raised: rgba(c::surface::RAISED),
            raised_hover: rgba(c::surface::RAISED_HOVER),
            overlay: rgba(c::surface::OVERLAY),
            primary: rgba(c::ink::PRIMARY),
            secondary: rgba(c::ink::SECONDARY),
            subtle: rgba(c::line::SUBTLE),
            strong: rgba(c::line::STRONG),
            control: rgba(c::line::CONTROL),
            accent_ink: rgba(c::accent::INK),
            accent_soft: rgba(c::accent::SOFT),
            focus: rgba(c::FOCUS),
            warn: rgba(c::warn::INK),
            bad: rgba(c::bad::INK),
            menu: elevation::dark::MENU,
            modal: elevation::dark::MODAL,
        },
    )
}

fn light() -> egui::Visuals {
    use color::light as c;
    visuals(
        egui::Visuals::light(),
        &Roles {
            ground: rgba(c::surface::GROUND),
            panel: rgba(c::surface::PANEL),
            inset: rgba(c::surface::INSET),
            raised: rgba(c::surface::RAISED),
            raised_hover: rgba(c::surface::RAISED_HOVER),
            overlay: rgba(c::surface::OVERLAY),
            primary: rgba(c::ink::PRIMARY),
            secondary: rgba(c::ink::SECONDARY),
            subtle: rgba(c::line::SUBTLE),
            strong: rgba(c::line::STRONG),
            control: rgba(c::line::CONTROL),
            accent_ink: rgba(c::accent::INK),
            accent_soft: rgba(c::accent::SOFT),
            focus: rgba(c::FOCUS),
            warn: rgba(c::warn::INK),
            bad: rgba(c::bad::INK),
            menu: elevation::light::MENU,
            modal: elevation::light::MODAL,
        },
    )
}

fn shadow(s: crate::tokens::Shadow) -> Shadow {
    // egui's shadows are whole pixels; the tokens are too.
    Shadow {
        offset: [s.offset_x as i8, s.offset_y as i8],
        blur: s.blur as u8,
        spread: s.spread as u8,
        color: rgba(s.color),
    }
}

fn visuals(mut v: egui::Visuals, r: &Roles) -> egui::Visuals {
    let control = CornerRadius::same(radius::regular::CONTROL as u8);
    let overlay = CornerRadius::same(radius::regular::OVERLAY as u8);

    // Plain text is what the screen is about; weak text is the supporting line.
    v.override_text_color = None;
    v.weak_text_color = Some(r.secondary);
    v.hyperlink_color = r.accent_ink;
    v.warn_fg_color = r.warn;
    v.error_fg_color = r.bad;

    v.panel_fill = r.panel;
    v.faint_bg_color = r.inset;
    v.extreme_bg_color = r.ground;
    v.text_edit_bg_color = Some(r.inset);
    v.code_bg_color = r.inset;
    v.window_fill = r.overlay;
    v.window_stroke = Stroke::new(1.0, r.strong);
    v.window_corner_radius = overlay;
    v.menu_corner_radius = overlay;
    v.window_shadow = shadow(r.modal);
    v.popup_shadow = shadow(r.menu);

    // The selection: the stream playing, the port chosen.
    v.selection.bg_fill = r.accent_soft;
    v.selection.stroke = Stroke::new(1.0, r.accent_ink);

    let w = &mut v.widgets;
    // Labels, separators, the grid's lines.
    w.noninteractive.bg_fill = r.panel;
    w.noninteractive.weak_bg_fill = r.panel;
    w.noninteractive.bg_stroke = Stroke::new(1.0, r.subtle);
    w.noninteractive.fg_stroke = Stroke::new(1.0, r.primary);
    w.noninteractive.corner_radius = control;
    // At rest. egui draws a button's edge and a checkbox's box with the same
    // stroke, and a checkbox needs an edge at 3:1, so both take the control line.
    w.inactive.bg_fill = r.raised;
    w.inactive.weak_bg_fill = r.raised;
    w.inactive.bg_stroke = Stroke::new(1.0, r.control);
    w.inactive.fg_stroke = Stroke::new(1.0, r.primary);
    w.inactive.corner_radius = control;
    w.inactive.expansion = 0.0;
    // Under the pointer.
    w.hovered.bg_fill = r.raised_hover;
    w.hovered.weak_bg_fill = r.raised_hover;
    w.hovered.bg_stroke = Stroke::new(1.0, r.control);
    w.hovered.fg_stroke = Stroke::new(1.0, r.primary);
    w.hovered.corner_radius = control;
    w.hovered.expansion = 0.0;
    // Held down, and keyboard focus, which egui draws with the same style: the
    // control sinks, and the focus ring is its edge.
    w.active.bg_fill = r.inset;
    w.active.weak_bg_fill = r.inset;
    w.active.bg_stroke = Stroke::new(2.0, r.focus);
    w.active.fg_stroke = Stroke::new(1.0, r.primary);
    w.active.corner_radius = control;
    w.active.expansion = 0.0;
    // A menu that is open.
    w.open.bg_fill = r.raised_hover;
    w.open.weak_bg_fill = r.raised_hover;
    w.open.bg_stroke = Stroke::new(1.0, r.control);
    w.open.fg_stroke = Stroke::new(1.0, r.primary);
    w.open.corner_radius = control;

    v
}

#[cfg(test)]
mod tests {
    use super::Motion;

    #[test]
    fn motion_follows_the_setting_then_the_os() {
        assert_eq!(Motion::from(Some("reduced"), || false), Motion::Reduced);
        assert_eq!(Motion::from(Some("full"), || true), Motion::Full);
        assert_eq!(Motion::from(None, || true), Motion::Reduced);
        assert_eq!(Motion::from(Some("anything else"), || false), Motion::Full);
    }

    #[test]
    fn reduced_motion_is_shorter_and_does_not_glide() {
        assert_eq!(Motion::Full.base(), 0.16);
        assert_eq!(Motion::Reduced.base(), 0.12);
        let mut style = eframe::egui::Style::default();
        Motion::Reduced.apply(&mut style);
        assert_eq!(style.animation_time, 0.12);
        assert_eq!(style.scroll_animation, eframe::egui::style::ScrollAnimation::none());
        assert_eq!(style.interaction.tooltip_delay, 0.5);
    }
}
