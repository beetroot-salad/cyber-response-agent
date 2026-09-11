| arm | fixture | n disp | completed | exact | error rate | unsupported/disp | reqs | retries | queries | q-err | $/disp | cached | reasoning tok | wall s | overlap |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| current | F1-off-hours-sudo | 49 | 82% | 90% (n=40) | 19% | 0.25 | 14.5 | 0.5 | 12.4 | 2.1 | 0.0685 | 86% | 19 | 59 | 1.1 |
| current | F2-authorized-keys | 19 | 68% | 91% (n=13) | 12% | 0.08 | 14.7 | 0.8 | 11.3 | 1.0 | 0.0766 | 85% | 0 | 52 | 1.2 |
| ds-flash | F1-off-hours-sudo | 45 | 100% | 88% (n=45) | 39% | 0.96 | 9.2 | 1.1 | 7.7 | 0.9 | 0.0073 | 81% | 0 | 44 | 1.6 |
| ds-flash | F2-authorized-keys | 21 | 86% | 93% (n=18) | 22% | 0.50 | 8.6 | 0.8 | 7.6 | 1.2 | 0.0066 | 84% | 0 | 33 | 2.1 |
| glm-flash | F1-off-hours-sudo | 47 | 100% | 94% (n=47) | 13% | 0.19 | 6.6 | 0.3 | 4.6 | 0.9 | 0.0046 | 80% | 372 | 35 | 1.5 |
| glm-flash | F2-authorized-keys | 21 | 90% | 97% (n=19) | 13% | 0.26 | 7.9 | 0.8 | 5.5 | 1.0 | 0.0058 | 74% | 437 | 48 | 1.2 |

| arm | fixture | runs | concluded | correct vs label | dispatches/run | $ gather/run | $ main/run | $ total/run |
|---|---|---|---|---|---|---|---|---|
| current | F1-off-hours-sudo | 5 | 5/5 | 0/5 | 9.8 | 0.671 | 0.363 | 1.105 |
| current | F2-authorized-keys | 3 | 3/3 | 3/3 | 6.3 | 0.485 | 0.272 | 0.911 |
| ds-flash | F1-off-hours-sudo | 5 | 5/5 | 0/5 | 9.0 | 0.066 | 0.360 | 0.459 |
| ds-flash | F2-authorized-keys | 3 | 3/3 | 3/3 | 7.0 | 0.046 | 0.292 | 0.469 |
| glm-flash | F1-off-hours-sudo | 6 | 6/6 | 0/6 | 7.8 | 0.036 | 0.218 | 0.430 |
| glm-flash | F2-authorized-keys | 3 | 3/3 | 0/3 | 7.0 | 0.041 | 0.311 | 0.352 |
