//! How the window looks: egui's visuals built from the shared design system's roles
//! (legofsalmon/design-system, vendored as `tokens.rs`), in both themes. The app
//! follows the system's theme, as it did on egui's own visuals.

use eframe::egui::{self, Color32, CornerRadius, Shadow, Stroke, Theme};

use crate::tokens::{color, elevation, radius};

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

/// Sets the visuals for both themes.
pub(crate) fn apply(ctx: &egui::Context) {
    ctx.set_visuals_of(Theme::Dark, dark());
    ctx.set_visuals_of(Theme::Light, light());
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
