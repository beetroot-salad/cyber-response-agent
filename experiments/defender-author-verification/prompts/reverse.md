You are evaluating a "lesson" generated from a SOC investigation. The lesson is meant to capture a generalizable pitfall — something the agent should avoid in the future. Your job is to assess whether the lesson is *interpretable*: a competent reader, given only the lesson and the original transcript, should be able to identify which moment in the investigation the lesson is correcting.

ORIGINAL TRANSCRIPT:

{transcript}

CANDIDATE LESSON:

{lesson}

TASK: Read the lesson. Then read the transcript. Identify the specific moment (PLAN/GATHER/ANALYZE/REPORT step or specific decision) the lesson is correcting. Then assess whether:
- the lesson points at a real, identifiable failure mode in this transcript, AND
- the lesson's recovery path is concrete enough to act on (specific check, threshold, or evidence requirement — not vague "be careful" advice).

OUTPUT FORMAT (strict):
First, name the moment and the failure mode in 1-3 sentences.
Then a final line, exactly: VERDICT: GOOD or VERDICT: BAD
- GOOD = the lesson clearly points at a real failure mode and gives a concrete recovery path.
- BAD = the lesson is vague, points at the wrong moment, mischaracterizes the failure, or its recovery path is not actionable.
