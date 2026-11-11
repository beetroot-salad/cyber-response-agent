# Builds the D15 wall-clock shim. The final image holds only the library, at /clockshim.so;
# `lab_ops.py` copies it into the `lab-clockshim` volume the frozen engine mounts at /lab/shim.
FROM gcc:13 AS build
COPY clockshim.c /src/clockshim.c
RUN gcc -shared -fPIC -O2 -o /clockshim.so /src/clockshim.c -ldl

FROM busybox:1.36
COPY --from=build /clockshim.so /clockshim.so
