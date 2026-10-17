# Learning-loop cutover (#922)

Historical context, not current operating instructions.

 Until the cutover the loop authored its own material: an actor
invented a story about the alert, an oracle invented the telemetry that story would have
produced, and a judge graded the defender against both — so everything it learned from was
imagined. The disposition selected which direction(s) ran, and two further corpora
(`lessons-actor/`, `lessons-environment/`) carried the actor-side observations. All of it is
deleted: the pipeline, the direction routing, the three extra queues and their curators, and the
`actor`/`oracle`/`judge` roles. `judge` came back in #1008 bound to the family judge, which
until then ran on the questioner's definition. `git show e9e11a48` is the deletion itself.
