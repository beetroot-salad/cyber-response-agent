| arm | fixture | n disp | completed | exact | error rate | unsupported/disp | reqs | retries | queries | q-err | $/disp | cached | reasoning tok | wall s | overlap |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| current | F1-off-hours-sudo | 11 | 91% | 92% (n=10) | 20% | 0.30 | 10.7 | 1.3 | 5.9 | 0.7 | 0.0411 | 86% | 85 | 41 | 1.3 |
| current | F2-authorized-keys | 7 | 71% | 87% (n=5) | 20% | 0.20 | 13.7 | 0.4 | 11.0 | 1.1 | 0.0738 | 87% | 0 | 61 | 1.4 |
| ds-flash | F1-off-hours-sudo | 10 | 100% | 95% (n=10) | 20% | 0.30 | 7.4 | 0.6 | 5.3 | 0.7 | 0.0062 | 71% | 0 | 27 | 1.7 |
| ds-flash | F2-authorized-keys | 8 | 88% | 90% (n=7) | 38% | 0.86 | 10.2 | 0.9 | 8.6 | 1.4 | 0.0078 | 86% | 0 | 41 | 2.0 |
| glm-flash | F1-off-hours-sudo | 6 | 100% | 87% (n=6) | 24% | 0.33 | 7.8 | 0.0 | 6.0 | 2.0 | 0.0079 | 70% | 768 | 32 | 1.3 |
| glm-flash | F2-authorized-keys | 6 | 83% | 93% (n=5) | 23% | 0.40 | 7.5 | 0.8 | 4.7 | 0.7 | 0.0053 | 78% | 430 | 22 | 1.8 |

| arm | fixture | runs | concluded | correct vs label | dispatches/run | $ gather/run | $ main/run | $ total/run |
|---|---|---|---|---|---|---|---|---|
| current | F1-off-hours-sudo | 1 | 1/1 | 0/1 | 11.0 | 0.452 | 0.305 | 0.757 |
| current | F2-authorized-keys | 1 | 1/1 | 1/1 | 7.0 | 0.517 | 0.247 | 1.001 |
| ds-flash | F1-off-hours-sudo | 1 | 1/1 | 0/1 | 10.0 | 0.061 | 0.421 | 0.483 |
| ds-flash | F2-authorized-keys | 1 | 1/1 | 1/1 | 8.0 | 0.062 | 0.283 | 0.486 |
| glm-flash | F1-off-hours-sudo | 1 | 1/1 | 0/1 | 6.0 | 0.047 | 0.145 | 0.295 |
| glm-flash | F2-authorized-keys | 1 | 1/1 | 0/1 | 6.0 | 0.032 | 0.220 | 0.251 |
