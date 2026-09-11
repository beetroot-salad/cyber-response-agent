| arm | fixture | n disp | completed | exact | error rate | unsupported/disp | reqs | retries | queries | q-err | $/disp | cached | reasoning tok | wall s | overlap |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| current | F1-off-hours-sudo | 35 | 83% | 93% (n=29) | 16% | 0.24 | 14.5 | 0.5 | 12.9 | 2.1 | 0.0703 | 86% | 27 | 63 | 1.1 |
| current | F2-authorized-keys | 19 | 68% | 91% (n=13) | 12% | 0.08 | 14.7 | 0.8 | 11.3 | 1.0 | 0.0766 | 85% | 0 | 52 | 1.2 |
| ds-flash | F1-off-hours-sudo | 30 | 100% | 89% (n=30) | 45% | 1.03 | 7.9 | 0.8 | 6.8 | 0.7 | 0.0064 | 78% | 0 | 36 | 1.6 |
| ds-flash | F2-authorized-keys | 21 | 86% | 93% (n=18) | 22% | 0.50 | 8.6 | 0.8 | 7.6 | 1.2 | 0.0066 | 84% | 0 | 33 | 2.1 |
| glm-flash | F1-off-hours-sudo | 21 | 100% | 94% (n=21) | 12% | 0.19 | 7.4 | 0.1 | 5.5 | 1.4 | 0.0059 | 80% | 496 | 52 | 1.3 |
| glm-flash | F2-authorized-keys | 21 | 90% | 97% (n=19) | 13% | 0.26 | 7.9 | 0.8 | 5.5 | 1.0 | 0.0058 | 74% | 437 | 48 | 1.2 |

| arm | fixture | runs | concluded | correct vs label | dispatches/run | $ gather/run | $ main/run | $ total/run |
|---|---|---|---|---|---|---|---|---|
| current | F1-off-hours-sudo | 3 | 3/3 | 0/3 | 11.7 | 0.821 | 0.423 | 1.244 |
| current | F2-authorized-keys | 3 | 3/3 | 3/3 | 6.3 | 0.485 | 0.272 | 0.911 |
| ds-flash | F1-off-hours-sudo | 3 | 3/3 | 0/3 | 10.0 | 0.064 | 0.416 | 0.480 |
| ds-flash | F2-authorized-keys | 3 | 3/3 | 3/3 | 7.0 | 0.046 | 0.292 | 0.469 |
| glm-flash | F1-off-hours-sudo | 3 | 3/3 | 0/3 | 7.0 | 0.041 | 0.181 | 0.374 |
| glm-flash | F2-authorized-keys | 3 | 3/3 | 0/3 | 7.0 | 0.041 | 0.311 | 0.352 |
