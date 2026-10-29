# Working on st2110

## Design

This app follows the shared design system in
[legofsalmon/design-system](https://github.com/legofsalmon/design-system),
checked out beside this repository as `../design-system`. Before changing
anything a person sees or touches, read its `docs/designing.md` and answer its
questions, then the pages it points to: `principles.md` (who uses these tools
and where, the colour grammar, type, space and the behaviour rules),
`behavioural.md` (how crew behave while getting a job done), `nngroup.md`
(the usability research and the ten heuristics every change is checked
against), `navigation.md`, `states.md`, `components.md` and `motion.md`.

- **Write the reasoning down.** A PR that changes what a person sees or
  touches has a short **Design** section: the one job of the view, the
  behaviour it designs for with the effect named (Default Effect, Loss
  Aversion, Time Scarcity…), any departure from the system and why, and
  any problem the heuristic check rated 3 that it leaves open. A bug fix
  that changes no design says so.
- **Use the system's parts first.** Its roles rather than literal colours,
  and a shared component's states, keys and wording before drawing a new one.
- **Send back what you learn.** A gap in the system, a departure that was
  right, something crew did that the rules did not predict, or a meaning of
  this app's that another app now needs: add it to the design system's
  `docs/learnings.md` in a PR there, or list it under **Learnings** in this
  PR's Design section so it can be carried across.
- **What stays this app's own:** storage and wire names, layout and flow,
  content, and meanings only this app has.

st2110 is on the system in both of its faces. The router page
(`crates/cli/src/router/page.html`) inlines the tokens, `base.css` and
`components.css` and is `data-theme="auto"` at the regular density; the
viewer vendors `tokens.rs` and draws egui's widgets in the shared states in
`look.rs`, in both themes. The design system's checker, vendored in
`scripts/ds/`, runs in CI (a hand edit fails, behind warns); add `--sync` to its
CI command to refill the copies from `../design-system`. Its own
meanings stay local: the tally (ROUTED, a local `--tally` on the bad family)
and the scrim behind the viewer's warning over video.
