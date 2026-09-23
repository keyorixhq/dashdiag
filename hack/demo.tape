# hack/demo.tape — recorded with VHS (https://github.com/charmbracelet/vhs).
# Produces docs/assets/demo.gif for README.md's "Try it in 10 seconds"
# section. Regenerate with: make demo-gif (requires `vhs` on PATH; the
# target skips gracefully with an install hint when it isn't installed).
#
# VHS sizes the terminal in PIXELS (Width/Height), not columns/rows — the
# Width/Height below approximate a 100-column x 32-row terminal at FontSize
# 16 (cell ~9.6px wide x ~19.2px tall: 100*9.6≈960, 32*19.2≈614), not an
# exact cell count.

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 970
Set Height 620
Set Theme "Dracula"
Set Padding 12
Set TypingSpeed 60ms

Type "dsd demo"
Enter
Sleep 6.5s

# Hold the final frame so a viewer has time to read the last line before
# the GIF loops.
Sleep 1.5s
