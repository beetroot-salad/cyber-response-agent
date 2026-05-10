You are evaluating a candidate "lesson" that the SOC defender agent would consult during investigation. Your job is to predict whether the lesson, if applied, would lead the agent to a correct disposition on the case it was generated from.

CASE TRANSCRIPT (the original investigation, including its actual evidence and disposition):

{transcript}

CANDIDATE LESSON:

{lesson}

CASE GROUND-TRUTH DISPOSITION: {disposition}

TASK: Imagine the defender agent has this lesson loaded at PLAN time on this same case. Read the lesson's recovery path. Reason about what the agent would do differently with this lesson loaded — would it still reach the ground-truth disposition, or would the lesson push it toward a different conclusion?

OUTPUT FORMAT (strict):
First, two short paragraphs of reasoning.
Then a final line, exactly: VERDICT: GOOD or VERDICT: BAD
- GOOD = applying this lesson would still produce the ground-truth disposition (lesson is safe to commit on this case).
- BAD = applying this lesson would push the agent toward a different disposition than ground truth (lesson is unsafe).
