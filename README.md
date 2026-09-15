KW66 Morse Messenger — v5

Changes:
- No tap-duration recognition.
- D1 09 = dot; D1 08 = dash.
- No Previous/Next debounce or duplicate filtering in this iteration.
- Timing is used only for boundaries.
- 900 ms after the last Morse element: commit the letter.
- 1800 ms after the last Morse element: commit the letter and insert a space.
- Manual Play remains: 1 = commit/space, 2 = send, 3+ = delete.
- Delete removes an unfinished Morse sequence first; otherwise the last character/space.
- Dictionary correction now has a word-boundary layer. It can repair strong cases of missing/wrong spaces, while avoiding fuzzy boundary guesses.
- Existing preview/cancel/send encryption flow is preserved.

Files:
- kw66_morse_v5.patch — patch for current GitHub app.js
- dict.js — replacement dictionary module
