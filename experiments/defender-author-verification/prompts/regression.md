You are evaluating whether a candidate "lesson" for the SOC defender agent would cause regressions on cases other than the one it was generated from. Your job is to imagine the lesson loaded at PLAN time on a *different* but realistic case in the same signature family, and predict whether the lesson would push the agent to an incorrect disposition on that other case.

ORIGINAL CASE TRANSCRIPT (the case the lesson came from):

{transcript}

CANDIDATE LESSON:

{lesson}

TASK: Construct a plausible hypothetical case in the same signature family that would land at a *different* disposition than the original (e.g., if the original is benign, imagine a case that should be malicious, or vice versa — or imagine a benign-but-different-mechanism variant). Reason about what would happen if the agent applied this lesson to that hypothetical case. Would the lesson push the agent toward the wrong disposition on that case?

You should reject the lesson if it overgeneralizes from the original case in a way that would systematically misclassify reasonable variants — even if it is correct on the original case.

OUTPUT FORMAT (strict):
First, name the hypothetical case in 1-2 sentences.
Then 1-2 sentences on what the lesson would do on that hypothetical case.
Then a final line, exactly: VERDICT: GOOD or VERDICT: BAD
- GOOD = the lesson would behave reasonably on plausible variants in the same signature family.
- BAD = the lesson would systematically misclassify reasonable variants.
