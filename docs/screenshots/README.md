# Screenshots

This repository carries no screenshots.

`vibe-vpn` is a command line program. There is no window to photograph, and
the things a screenshot would show are text: a statistics line, a setup
transcript, the output of `vibe-vpn status`. A picture of a terminal is a
picture of somebody's shell, with their paths and their prompt in it.

The output that matters is in the documents instead. `../protocol.md` holds
the frame layouts, `../architecture.md` holds the layer diagram and the
module table, and the README holds the list of message types with their
values and their direction.

The repository does carry one diagram, in the README: the ASCII drawing of
the TUN device, the session layer, the framing and the transport. It is
drawn in text on purpose, because it renders in a terminal, on GitHub and in
a plain text file alike, and it is not a picture of anything.

If a screenshot is ever added, it goes in this folder and the document that
uses it links to it by relative path, so that it resolves both on GitHub
and in a local checkout. The house-style checker verifies that every image
reference points at a file that exists.
